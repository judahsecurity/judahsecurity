"""Small, metered port checks for an analyst-supervised host pilot.

Results are observations, not vulnerability findings. In particular, silence
from UDP is inconclusive and a TCP connect does not identify an application.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from app.services.agent.pilot_policy import PilotDenied, PilotPolicy, exact_origin


def parse_ports(ports: list[int] | str) -> list[int]:
    if isinstance(ports, str):
        values = ports.split(",")
        if any(not value.strip().isdigit() for value in values):
            raise PilotDenied("Ports must be comma-separated numbers, without ranges")
        ports = [int(value.strip()) for value in values]
    if not isinstance(ports, list) or not ports or len(ports) > 20:
        raise PilotDenied("Provide 1 to 20 ports per approved action")
    if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
           for port in ports):
        raise PilotDenied("Ports must be integers from 1 to 65535")
    if len(set(ports)) != len(ports):
        raise PilotDenied("Duplicate ports in one action are not allowed")
    return ports


async def resolve_public_address(host: str, protocol: str) -> str:
    """Choose one public DNS address and expose that limit in each result."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            raise PilotDenied("Pilot target resolved to a non-public address")
        return str(address)
    loop = asyncio.get_running_loop()
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    try:
        answers = await loop.getaddrinfo(host, None, type=sock_type)
    except OSError as exc:
        raise PilotDenied("Pilot target DNS resolution failed") from exc
    addresses = sorted({item[4][0] for item in answers})
    if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise PilotDenied("Pilot target DNS includes a non-public address")
    return addresses[0]


async def _tcp_probe(address: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=2.0,
        )
    except ConnectionRefusedError:
        return {"state": "closed"}
    except (asyncio.TimeoutError, OSError):
        return {"state": "filtered_or_unreachable"}
    try:
        try:
            banner = await asyncio.wait_for(reader.read(64), timeout=0.3)
        except asyncio.TimeoutError:
            banner = b""
        return {"state": "open", "banner_hex": banner.hex() if banner else None}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def _udp_probe(address: str, port: int) -> dict:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        sock.connect((address, port))
        await loop.sock_sendall(sock, b"\x00")
        try:
            response = await asyncio.wait_for(loop.sock_recv(sock, 64), timeout=1.0)
        except ConnectionRefusedError:
            return {"state": "closed"}
        except asyncio.TimeoutError:
            return {"state": "open_or_filtered", "note": "No UDP response; inconclusive"}
        return {"state": "responded", "banner_hex": response.hex()}
    except OSError:
        return {"state": "unreachable_or_filtered"}
    finally:
        sock.close()


async def probe_ports(policy: PilotPolicy, protocol: str, ports: list[int] | str) -> dict:
    selected = parse_ports(ports)
    if protocol not in {"tcp", "udp"}:
        raise PilotDenied("Protocol must be tcp or udp")
    host = exact_origin(policy.target)[1]
    address = await resolve_public_address(host, protocol)
    observations = []
    stopped_reason = None
    for port in selected:
        try:
            count = await policy.acquire_port_probe(port, protocol)
        except PilotDenied as exc:
            stopped_reason = str(exc)
            break
        outcome = await (_tcp_probe(address, port) if protocol == "tcp"
                         else _udp_probe(address, port))
        observations.append({"port": port, "protocol": protocol, "ip": address,
                             "budget_count": count, **outcome})
    if stopped_reason and not observations:
        raise PilotDenied(stopped_reason)
    return {"host": host, "scanned_ip": address, "protocol": protocol,
            "observations": observations,
            "complete": stopped_reason is None,
            "stopped_reason": stopped_reason,
            "coverage_note": "One public DNS address tested; service identity and other addresses remain unverified."}
