"""
Ownership pivots - pure parsing helpers for root-domain ownership discovery.

These turn records that an organization controls (SPF / DMARC / MX / NS,
homepage tracking IDs, favicon) into *candidate* owned domains. Everything
here is network-free so it can be unit tested; the HTTP / DNS calls live in
``ExternalDiscoveryService``.

Candidates are deliberately filtered against large shared-provider lists:
``include:spf.protection.outlook.com`` says nothing about who owns a domain,
``include:_spf.rockwellautomation.com`` does.
"""

from __future__ import annotations

import base64
import re
from typing import Dict, Iterable, List, Optional, Set

# ---------------------------------------------------------------------------
# Registrable-domain reduction
# ---------------------------------------------------------------------------

# Multi-label public suffixes that show up in enterprise portfolios. Not a full
# PSL (no new dependency), but covers the ccTLD second levels that matter for
# multinational org discovery (e.g. rockwellautomation.co.jp / .com.cn).
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.hk", "org.hk", "net.hk",
    "com.tw", "org.tw", "net.tw",
    "com.sg", "org.sg", "net.sg",
    "com.my", "net.my", "org.my",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "com.mx", "org.mx", "net.mx", "gob.mx",
    "com.ar", "org.ar", "net.ar",
    "com.co", "net.co", "org.co",
    "com.tr", "net.tr", "org.tr",
    "co.za", "org.za", "net.za",
    "co.id", "or.id", "web.id",
    "co.th", "in.th", "or.th",
    "com.ph", "net.ph", "org.ph",
    "com.vn", "net.vn",
    "com.pl", "net.pl", "org.pl",
    "com.ru", "net.ru", "org.ru",
    "com.ua", "net.ua", "org.ua",
    "com.sa", "net.sa", "org.sa",
    "com.eg", "com.pe", "com.ve", "com.ec", "com.uy", "com.py", "com.bo",
    "co.il", "org.il", "net.il",
    "co.at", "or.at",
    "com.es", "org.es", "nom.es",
    "com.pt", "com.gr", "com.cy", "com.mt",
}

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def registrable_domain(host: str) -> str:
    """Reduce a hostname / URL / email to its registrable domain (best effort)."""
    h = (host or "").strip().lower()
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0].split(":", 1)[0].strip(".")
    if h.startswith("*."):
        h = h[2:]
    parts = [p for p in h.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


def is_hostname(value: str) -> bool:
    return bool(_HOST_RE.match((value or "").strip().lower().strip(".")))


# ---------------------------------------------------------------------------
# Shared-provider filters
# ---------------------------------------------------------------------------

# Registrable domains of email / SPF / DMARC / DNS service providers. An SPF
# include or DMARC report address on one of these is NOT an ownership signal.
SHARED_MAIL_PROVIDERS: Set[str] = {
    # Mailbox / gateway
    "outlook.com", "office365.com", "microsoft.com", "hotmail.com", "google.com",
    "googlemail.com", "gmail.com", "pphosted.com", "ppe-hosted.com", "proofpoint.com",
    "mimecast.com", "mimecast-offshore.com", "messagelabs.com", "symantec.com",
    "barracudanetworks.com", "barracuda.com", "cisco.com", "iphmx.com", "ironport.com",
    "trendmicro.com", "trendmicro.eu", "sophos.com", "forcepoint.com", "mailcontrol.com",
    "fireeyecloud.com", "zoho.com", "zoho.eu", "yahoo.com", "aol.com", "icloud.com",
    "apple.com", "secureserver.net", "emailsrvr.com", "rackspace.com", "ovh.net",
    "1and1.com", "ionos.com", "fastmail.com", "protonmail.ch", "yandex.net",
    "amazonaws.com", "amazonses.com", "awsapps.com", "messaging.microsoft.com",
    "hornetsecurity.com", "spamexperts.com", "antispamcloud.com", "mailgun.org",
    # Bulk / transactional / marketing senders
    "sendgrid.net", "sendgrid.com", "mailgun.com", "mandrillapp.com", "mailchimp.com",
    "mcsv.net", "mcdlv.net", "rsgsv.net", "mailjet.com", "sparkpostmail.com",
    "sparkpost.com", "postmarkapp.com", "mtasv.net", "sendinblue.com", "brevo.com",
    "constantcontact.com", "ctctcdn.com", "exacttarget.com", "salesforce.com",
    "force.com", "pardot.com", "marketo.com", "mktomail.com", "mktdns.com",
    "hubspot.com", "hubspotemail.net", "eloqua.com", "oracle.com", "responsys.net",
    "zendesk.com", "freshdesk.com", "servicenow.com", "service-now.com",
    "atlassian.net", "atlassian.com", "jira.com", "intercom.io", "helpscout.net",
    "docusign.net", "docusign.com", "adobe.com", "workday.com", "successfactors.com",
    "sap.com", "ariba.com", "coupahost.com", "concursolutions.com", "smartsheet.com",
    "qualtrics.com", "surveymonkey.com", "cvent.com", "on24.com", "zoom.us",
    "webex.com", "gotomeeting.com", "ringcentral.com", "twilio.com", "sendgrid.info",
    "mailgun.net", "elasticemail.com", "socketlabs.com", "smtp2go.com", "mailersend.net",
    "emarsys.net", "dotmailer.com", "dotdigital.com", "acoustic.com", "silverpop.com",
    "sailthru.com", "braze.com", "iterable.com", "klaviyo.com", "cust-spf.exacttarget.com",
    "everbridge.net", "smtp.com", "spf-protect.com", "dynect.net",
    # DMARC report processors
    "dmarcian.com", "dmarcian.eu", "agari.com", "valimail.com", "ondmarc.com",
    "redsift.cloud", "dmarcanalyzer.com", "easydmarc.com", "easydmarc.us",
    "uriports.com", "postmarkapp.com", "dmarc.report", "dmarcadvisor.com",
    "returnpath.net", "250ok.com", "proofpoint-dmarc.com", "mxtoolbox.com",
    "emaildefense.proofpoint.com", "fraudmarc.com", "dmarc.postmarkapp.com",
    "rua.agari.com", "vali.email", "powerdmarc.com", "sendmarc.com", "dmarcly.com",
    "cloudflare.net", "cloudflare.com", "mailhardener.com", "global.dmarcpro.com",
}

SHARED_DNS_HOSTING: Set[str] = {
    "awsdns-01.com", "awsdns.com", "awsdns.net", "awsdns.org", "azure-dns.com",
    "azure-dns.net", "azure-dns.org", "azure-dns.info", "cloudflare.com",
    "googledomains.com", "google.com", "domaincontrol.com", "registrar-servers.com",
    "nsone.net", "ultradns.com", "ultradns.net", "ultradns.org", "ultradns.biz",
    "ultradns.info", "dynect.net", "akam.net", "akamaiedge.net", "akamai.net",
    "cscdns.net", "cscdns.uk", "markmonitor.com", "mmdns.net", "verisign-grs.com",
    "worldnic.com", "dnsmadeeasy.com", "dnsimple.com", "linode.com",
    "digitalocean.com", "hostgator.com", "bluehost.com", "name-services.com",
    "gandi.net", "ovh.net", "hetzner.com", "zoneedit.com", "easydns.com",
    "easydns.net", "afternic.com", "sedoparking.com", "parkingcrew.net",
    "bodis.com", "above.com", "dns.com", "1and1.com", "ui-dns.com", "ui-dns.de",
    "ui-dns.org", "ui-dns.biz", "safenames.net", "comlaude-dns.com", "comlaude.net",
    "nic.ru", "edgedns.com", "msft.net", "microsoftonline.com", "netlify.com",
    "vercel-dns.com", "wixdns.net", "squarespacedns.com", "shopify.com",
    "outlook.com", "pphosted.com", "mimecast.com", "google.com", "googlemail.com",
}

# Registrant emails on these domains are registrar/proxy role accounts shared
# across huge portfolios; reverse-WHOIS on them is useless or ruinously broad.
REGISTRAR_ROLE_EMAIL_DOMAINS: Set[str] = {
    "markmonitor.com", "cscglobal.com", "cscinfo.com", "corporatedomains.com",
    "godaddy.com", "domainsbyproxy.com", "whoisguard.com", "privacyprotect.org",
    "withheldforprivacy.com", "contactprivacy.com", "networksolutions.com",
    "web.com", "tucows.com", "namecheap.com", "gandi.net", "ovh.net", "ovh.com",
    "safenames.net", "comlaude.com", "brandsight.com", "1and1.com", "ionos.com",
    "registrar.amazon.com", "amazon.com", "identity-protect.org", "privacyguardian.org",
    "domainprivacygroup.com", "whoisprivacycorp.com", "anonymize.com",
    "perfectprivacy.com", "proxy.dreamhost.com", "dreamhost.com", "dynadot.com",
    "porkbun.com", "namesilo.com", "hover.com", "enom.com", "register.com",
    "registrarsafe.com", "nic.ru", "key-systems.net", "secureserver.net",
    "google.com", "squarespace.com", "domains.google", "cloudflare.com",
    "eurodns.com", "101domain.com", "lexsynergy.com", "nameshield.net",
    "ebrand.com", "authenticweb.com", "clarivate.com", "valideus.com",
}

_ROLE_LOCAL_PARTS = ("abuse", "privacy", "proxy", "whois", "redacted", "noreply", "no-reply")


def is_usable_registrant_email(email: str) -> bool:
    """True when reverse-WHOIS on ``email`` can plausibly return an org portfolio."""
    e = (email or "").strip().lower()
    if "@" not in e:
        return False
    local, _, dom = e.rpartition("@")
    if any(tok in local for tok in _ROLE_LOCAL_PARTS):
        return False
    if any(tok in dom for tok in ("privacy", "proxy", "redacted", "whoisguard", "protect")):
        return False
    return registrable_domain(dom) not in REGISTRAR_ROLE_EMAIL_DOMAINS


def is_shared_provider(host: str) -> bool:
    reg = registrable_domain(host)
    return reg in SHARED_MAIL_PROVIDERS or reg in SHARED_DNS_HOSTING


# ---------------------------------------------------------------------------
# SPF / DMARC
# ---------------------------------------------------------------------------

def parse_spf(txt_records: Iterable[str]) -> Dict[str, List[str]]:
    """
    Pull ``include:`` / ``redirect=`` / ``exists:`` / ``a:`` / ``mx:`` targets
    out of SPF TXT records. Returns {"includes": [...], "redirects": [...],
    "hosts": [...]} of hostnames (macros stripped).
    """
    out = {"includes": [], "redirects": [], "hosts": []}
    for raw in txt_records or []:
        rec = _join_txt(raw).strip()
        if not rec.lower().startswith("v=spf1"):
            continue
        for term in rec.split()[1:]:
            t = term.lstrip("+-~?")
            low = t.lower()
            target = None
            bucket = "hosts"
            if low.startswith("include:"):
                target, bucket = t[8:], "includes"
            elif low.startswith("redirect="):
                target, bucket = t[9:], "redirects"
            elif low.startswith("exists:"):
                target = t[7:]
            elif low.startswith("a:") or low.startswith("mx:"):
                target = t.split(":", 1)[1]
            if not target:
                continue
            target = target.split("/", 1)[0]
            # Drop SPF macros (%{i}.%{h}._spf.example.com -> _spf.example.com)
            labels = target.split(".")
            macro_idx = [i for i, p in enumerate(labels) if "%" in p or "{" in p]
            if macro_idx:
                # Keep the static zone after the last macro label
                labels = labels[macro_idx[-1] + 1:]
            target = ".".join(labels)
            target = target.strip(".").lower()
            if target and "." in target:
                out[bucket].append(target)
    return out


def parse_dmarc(txt_records: Iterable[str]) -> List[str]:
    """Return the email addresses in a DMARC record's ``rua`` / ``ruf`` tags."""
    emails: List[str] = []
    for raw in txt_records or []:
        rec = _join_txt(raw).strip()
        if not rec.lower().startswith("v=dmarc1"):
            continue
        for tag in rec.split(";"):
            k, _, v = tag.strip().partition("=")
            if k.strip().lower() not in ("rua", "ruf"):
                continue
            for uri in v.split(","):
                uri = uri.strip()
                if uri.lower().startswith("mailto:"):
                    addr = uri[7:].split("!", 1)[0].strip().lower()
                    if "@" in addr:
                        emails.append(addr)
    return emails


def _join_txt(raw: str) -> str:
    """dnspython renders multi-string TXT as '"part1" "part2"'; join them."""
    s = str(raw or "")
    if '"' in s:
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', s)
        if parts:
            return "".join(parts)
    return s


def candidate_domains_from_hosts(
    hosts: Iterable[str], exclude: Iterable[str] = ()
) -> List[str]:
    """Registrable domains of ``hosts`` minus shared providers and ``exclude``."""
    excluded = {registrable_domain(e) for e in exclude if e}
    out: List[str] = []
    for h in hosts or []:
        reg = registrable_domain(h)
        if not reg or not is_hostname(reg) or reg in excluded or is_shared_provider(reg):
            continue
        if reg not in out:
            out.append(reg)
    return out


# ---------------------------------------------------------------------------
# Homepage fingerprints: tracking IDs + favicon
# ---------------------------------------------------------------------------

_TRACKING_PATTERNS = {
    "ua": re.compile(r"\b(UA-\d{4,10})-\d{1,4}\b"),
    "ga4": re.compile(r"""['"(=\s/](G-[A-Z0-9]{8,12})\b"""),
    "gtm": re.compile(r"\b(GTM-[A-Z0-9]{5,9})\b"),
    "adsense": re.compile(r"\b(?:ca-)?(pub-\d{10,20})\b"),
}


def extract_tracking_ids(html: str) -> Dict[str, List[str]]:
    """
    Extract analytics / tag-manager / AdSense IDs from page HTML.

    Universal Analytics IDs are reduced to the *account* (``UA-1234567``):
    properties under one account share an owner, which is the pivot we want.
    """
    found: Dict[str, List[str]] = {}
    text = html or ""
    for kind, pat in _TRACKING_PATTERNS.items():
        ids = list(dict.fromkeys(m.group(1) for m in pat.finditer(text)))
        if ids:
            found[kind] = ids
    return found


_ICON_LINK_RE = re.compile(
    r"""<link\b[^>]*\brel\s*=\s*["'][^"']*\bicon\b[^"']*["'][^>]*>""", re.IGNORECASE
)
_HREF_RE = re.compile(r"""\bhref\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def find_favicon_href(html: str) -> Optional[str]:
    for tag in _ICON_LINK_RE.findall(html or ""):
        m = _HREF_RE.search(tag)
        if m:
            return m.group(1).strip()
    return None


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, signed - identical to ``mmh3.hash``."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = length & ~0x3
    for i in range(0, rounded, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = length & 0x3
    if tail == 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(content: bytes) -> int:
    """Shodan ``http.favicon.hash`` value: mmh3 of the base64 (76-col, \\n) body."""
    return murmur3_32(base64.encodebytes(content))
