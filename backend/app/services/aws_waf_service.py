"""AWS WAF (WAFv2) integration service.

Read-only import of AWS WAF Web ACLs and the hostnames/resources they protect
into the ASM platform:

    CLOUDFRONT scope → CloudFront distributions (domain name + CNAME aliases)
    REGIONAL scope   → Application Load Balancers (DNS name) and API Gateways
                       (execute-api endpoint) associated with each Web ACL

Each protected hostname becomes a DOMAIN/SUBDOMAIN asset tagged ``waf:aws``, and
each Web ACL is recorded as a CLOUD_RESOURCE asset. The integration never
modifies WAF rules, IP sets, or resource associations.

boto3 is imported lazily so the module (and its pure helpers) can be imported
without the AWS SDK present. All blocking AWS SDK calls run in a worker thread.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.aws_waf_integration import AwsWafIntegration

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "aws_waf"
WAF_TAG = "waf:aws"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"

# Regional resource types that AWS WAF can be associated with.
REGIONAL_RESOURCE_TYPES = (
    "APPLICATION_LOAD_BALANCER",
    "API_GATEWAY",
    "APPSYNC",
    "COGNITO_USER_POOL",
    "APP_RUNNER_SERVICE",
    "VERIFIED_ACCESS_INSTANCE",
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:\*\.)?(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)
_APIGW_ARN_RE = re.compile(
    r"^arn:aws[\w-]*:apigateway:(?P<region>[a-z0-9-]+)::/restapis/(?P<api_id>[A-Za-z0-9]+)"
)


# ── Pure helpers (no AWS SDK) ────────────────────────────────────────────────


def _clean_hostname(hostname: Any) -> Optional[str]:
    if not isinstance(hostname, str):
        return None
    name = hostname.strip().rstrip(".").lower()
    if not name or not _HOSTNAME_RE.match(name):
        return None
    return name


def _asset_type_for_hostname(hostname: str) -> AssetType:
    hn = hostname[2:] if hostname.startswith("*.") else hostname
    labels = [p for p in hn.split(".") if p]
    return AssetType.DOMAIN if len(labels) <= 2 else AssetType.SUBDOMAIN


def hostnames_from_distribution(distribution: Dict[str, Any]) -> List[str]:
    """Extract the domain name and CNAME aliases from a CloudFront distribution."""
    out: List[str] = []
    domain = _clean_hostname(distribution.get("DomainName"))
    if domain:
        out.append(domain)
    aliases = distribution.get("Aliases")
    if isinstance(aliases, dict):
        for item in aliases.get("Items") or []:
            hn = _clean_hostname(item)
            if hn:
                out.append(hn)
    # De-dup, preserve order.
    seen: set[str] = set()
    deduped: List[str] = []
    for hn in out:
        if hn not in seen:
            seen.add(hn)
            deduped.append(hn)
    return deduped


def apigw_endpoint_from_arn(arn: str) -> Optional[str]:
    """Derive the execute-api hostname from an API Gateway stage ARN."""
    if not isinstance(arn, str):
        return None
    m = _APIGW_ARN_RE.match(arn.strip())
    if not m:
        return None
    return f"{m.group('api_id')}.execute-api.{m.group('region')}.amazonaws.com"


# ── AWS SDK access (lazy boto3) ──────────────────────────────────────────────


def _session(access_key_id: str, secret_access_key: str, session_token: Optional[str]):
    import boto3  # lazy

    return boto3.session.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token or None,
    )


def _boto_config():
    from botocore.config import Config  # lazy

    return Config(connect_timeout=15, read_timeout=45, retries={"max_attempts": 3})


def _list_web_acls(client, scope: str) -> List[Dict[str, Any]]:
    acls: List[Dict[str, Any]] = []
    marker: Optional[str] = None
    for _ in range(200):
        kwargs: Dict[str, Any] = {"Scope": scope, "Limit": 100}
        if marker:
            kwargs["NextMarker"] = marker
        resp = client.list_web_acls(**kwargs)
        acls.extend(resp.get("WebACLs") or [])
        marker = resp.get("NextMarker")
        if not marker:
            break
    return acls


def _cloudfront_hostnames_by_acl(session, cfg) -> Dict[str, List[str]]:
    """Map CloudFront Web ACL ARN → protected hostnames (domain + aliases)."""
    client = session.client("cloudfront", config=cfg)
    by_acl: Dict[str, List[str]] = {}
    marker: Optional[str] = None
    for _ in range(500):
        kwargs: Dict[str, Any] = {"MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        resp = client.list_distributions(**kwargs)
        dist_list = resp.get("DistributionList") or {}
        for dist in dist_list.get("Items") or []:
            acl_id = dist.get("WebACLId")
            if not acl_id:
                continue
            by_acl.setdefault(acl_id, [])
            for hn in hostnames_from_distribution(dist):
                if hn not in by_acl[acl_id]:
                    by_acl[acl_id].append(hn)
        if dist_list.get("IsTruncated") and dist_list.get("NextMarker"):
            marker = dist_list["NextMarker"]
        else:
            break
    return by_acl


def _resolve_regional_hostnames(session, region: str, resource_arns: List[str]) -> List[str]:
    """Resolve ALB / API Gateway resource ARNs to hostnames."""
    hostnames: List[str] = []
    alb_arns = [a for a in resource_arns if ":loadbalancer/" in a]
    if alb_arns:
        try:
            elbv2 = session.client("elbv2", region_name=region, config=_boto_config())
            # describe_load_balancers accepts up to 20 ARNs per call.
            for i in range(0, len(alb_arns), 20):
                chunk = alb_arns[i : i + 20]
                resp = elbv2.describe_load_balancers(LoadBalancerArns=chunk)
                for lb in resp.get("LoadBalancers") or []:
                    hn = _clean_hostname(lb.get("DNSName"))
                    if hn:
                        hostnames.append(hn)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AWS WAF: ALB resolve failed in %s: %s", region, exc)

    for arn in resource_arns:
        endpoint = apigw_endpoint_from_arn(arn)
        if endpoint:
            hostnames.append(endpoint)

    seen: set[str] = set()
    out: List[str] = []
    for hn in hostnames:
        if hn not in seen:
            seen.add(hn)
            out.append(hn)
    return out


def _collect_web_acls(
    access_key_id: str,
    secret_access_key: str,
    session_token: Optional[str],
    regions: List[str],
    *,
    include_cloudfront: bool,
    include_regional: bool,
) -> List[Dict[str, Any]]:
    """Enumerate Web ACLs and the hostnames/resources they protect (blocking)."""
    session = _session(access_key_id, secret_access_key, session_token)
    cfg = _boto_config()
    results: List[Dict[str, Any]] = []

    if include_cloudfront:
        try:
            # CloudFront scope Web ACLs are managed from us-east-1.
            waf = session.client("wafv2", region_name="us-east-1", config=cfg)
            acls = _list_web_acls(waf, "CLOUDFRONT")
            cf_map = _cloudfront_hostnames_by_acl(session, cfg) if acls else {}
            for acl in acls:
                arn = acl.get("ARN") or ""
                results.append(
                    {
                        "name": acl.get("Name"),
                        "id": acl.get("Id"),
                        "arn": arn,
                        "scope": "CLOUDFRONT",
                        "region": "global",
                        "hostnames": cf_map.get(arn, []),
                        "resource_arns": [],
                    }
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("AWS WAF: CloudFront enumeration failed: %s", exc)

    if include_regional:
        for region in regions:
            try:
                waf = session.client("wafv2", region_name=region, config=cfg)
                acls = _list_web_acls(waf, "REGIONAL")
                for acl in acls:
                    arn = acl.get("ARN") or ""
                    resource_arns: List[str] = []
                    for rtype in REGIONAL_RESOURCE_TYPES:
                        try:
                            resp = waf.list_resources_for_web_acl(WebACLArn=arn, ResourceType=rtype)
                            resource_arns.extend(resp.get("ResourceArns") or [])
                        except Exception as exc:  # noqa: BLE001
                            logger.debug(
                                "AWS WAF: list_resources_for_web_acl(%s) failed in %s: %s",
                                rtype, region, exc,
                            )
                    hostnames = _resolve_regional_hostnames(session, region, resource_arns)
                    results.append(
                        {
                            "name": acl.get("Name"),
                            "id": acl.get("Id"),
                            "arn": arn,
                            "scope": "REGIONAL",
                            "region": region,
                            "hostnames": hostnames,
                            "resource_arns": resource_arns,
                        }
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("AWS WAF: regional enumeration failed in %s: %s", region, exc)

    return results


async def test_connection(
    access_key_id: str,
    secret_access_key: str,
    session_token: Optional[str],
    regions: List[str],
    *,
    include_cloudfront: bool = True,
    include_regional: bool = True,
) -> Dict[str, Any]:
    """Validate AWS credentials by listing Web ACLs."""
    def _probe() -> Tuple[bool, str, Optional[int]]:
        try:
            session = _session(access_key_id, secret_access_key, session_token)
            cfg = _boto_config()
            count = 0
            if include_cloudfront:
                waf = session.client("wafv2", region_name="us-east-1", config=cfg)
                count += len(_list_web_acls(waf, "CLOUDFRONT"))
            if include_regional:
                region = regions[0] if regions else "us-east-1"
                waf = session.client("wafv2", region_name=region, config=cfg)
                count += len(_list_web_acls(waf, "REGIONAL"))
            return True, "Connected to AWS WAF successfully.", count
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)[:500], None

    ok, message, count = await asyncio.to_thread(_probe)
    return {"ok": ok, "message": message, "web_acls_found": count}


# ── Asset ingestion ──────────────────────────────────────────────────────────


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.web_acls_seen = 0
        self.hostnames_seen = 0
        self.resources_seen = 0
        self.assets_missing_from_source = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "web_acls_seen": self.web_acls_seen,
            "hostnames_seen": self.hostnames_seen,
            "resources_seen": self.resources_seen,
            "assets_missing_from_source": self.assets_missing_from_source,
        }


def _upsert_asset(
    db: Session,
    integration: AwsWafIntegration,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    name: str,
    metadata: Dict[str, Any],
    description: Optional[str] = None,
) -> Optional[Asset]:
    value = (value or "").strip()
    if not value:
        return None

    org_id = integration.organization_id
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == value)
        .first()
    )

    desired_tags = {SOURCE_TAG, WAF_TAG}

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "aws_waf:removed"]
        for t in desired_tags:
            if t not in tags:
                tags.append(t)
        existing.tags = tags
        meta = dict(existing.metadata_ or {})
        meta.update(metadata)
        existing.metadata_ = meta
        if not existing.hosting_provider:
            existing.hosting_provider = "aws"
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=(name or value)[:255],
        asset_type=asset_type,
        value=value[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        description=description,
        discovery_source=DISCOVERY_SOURCE,
        association_reason="Protected by / imported from AWS WAF",
        association_confidence=90,
        tags=sorted(desired_tags),
        metadata_=metadata,
        hosting_provider="aws",
        hosting_type="waf",
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _import_web_acls(
    db: Session,
    integration: AwsWafIntegration,
    web_acls: List[Dict[str, Any]],
    stats: _Stats,
) -> set[str]:
    stats.web_acls_seen = len(web_acls)
    seen_values: set[str] = set()
    seen_hostnames: set[str] = set()

    for acl in web_acls:
        acl_id = acl.get("id") or acl.get("arn") or acl.get("name")
        acl_name = acl.get("name") or acl_id
        scope = acl.get("scope") or "REGIONAL"
        region = acl.get("region") or "global"
        hostnames = [hn for hn in (acl.get("hostnames") or []) if isinstance(hn, str)]
        resource_arns = acl.get("resource_arns") or []
        stats.resources_seen += len(resource_arns)

        # Web ACL as a CLOUD_RESOURCE asset.
        acl_value = f"aws-waf:{scope.lower()}:{acl_id}"
        _upsert_asset(
            db,
            integration,
            acl_value,
            AssetType.CLOUD_RESOURCE,
            stats,
            name=f"AWS WAF: {acl_name}",
            description=f"AWS WAFv2 Web ACL '{acl_name}' ({scope}, {region})",
            metadata={
                "aws_waf_integration_id": integration.id,
                "aws_waf_acl_name": acl_name,
                "aws_waf_acl_id": acl.get("id"),
                "aws_waf_acl_arn": acl.get("arn"),
                "aws_waf_scope": scope,
                "aws_waf_region": region,
                "aws_waf_hostnames": hostnames,
                "aws_waf_resource_arns": resource_arns,
                "asset_kind": "waf_web_acl",
                "source": DISCOVERY_SOURCE,
            },
        )
        seen_values.add(acl_value)

        for hn in hostnames:
            if hn in seen_hostnames:
                continue
            seen_hostnames.add(hn)
            stats.hostnames_seen += 1
            _upsert_asset(
                db,
                integration,
                hn,
                _asset_type_for_hostname(hn),
                stats,
                name=hn,
                description=f"Protected by AWS WAF Web ACL '{acl_name}'",
                metadata={
                    "aws_waf_integration_id": integration.id,
                    "aws_waf_acl_name": acl_name,
                    "aws_waf_scope": scope,
                    "aws_waf_region": region,
                    "protected_by_waf": True,
                    "source": DISCOVERY_SOURCE,
                },
            )
            seen_values.add(hn)

    return seen_values


def _mark_missing_assets(
    db: Session,
    integration: AwsWafIntegration,
    seen_values: set[str],
    stats: _Stats,
) -> None:
    prior = (
        db.query(Asset)
        .filter(
            Asset.organization_id == integration.organization_id,
            Asset.discovery_source == DISCOVERY_SOURCE,
        )
        .all()
    )
    for asset in prior:
        meta = asset.metadata_ or {}
        if meta.get("aws_waf_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "aws_waf:removed" not in tags:
                tags.append("aws_waf:removed")
                asset.tags = tags


async def sync_integration(db: Session, integration: AwsWafIntegration) -> Dict[str, Any]:
    """Import Web ACLs and protected hostnames from AWS WAF."""
    org_id = integration.organization_id
    stats = _Stats()

    access_key_id = integration.get_access_key_id()
    secret_access_key = integration.get_secret_access_key()
    if not access_key_id or not secret_access_key:
        return {
            "ok": False,
            "message": "No AWS credentials stored for this connection.",
            **stats.as_dict(),
        }

    try:
        web_acls = await asyncio.to_thread(
            _collect_web_acls,
            access_key_id,
            secret_access_key,
            integration.get_session_token(),
            list(integration.regions or ["us-east-1"]),
            include_cloudfront=bool(integration.include_cloudfront),
            include_regional=bool(integration.include_regional),
        )

        seen = _import_web_acls(db, integration, web_acls, stats)
        _mark_missing_assets(db, integration, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) from AWS WAF "
                f"({stats.web_acls_seen} Web ACL(s), {stats.hostnames_seen} protected hostname(s))."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("AWS WAF sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            **stats.as_dict(),
        }
