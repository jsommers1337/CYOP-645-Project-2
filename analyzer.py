"""Offline packet-capture analysis and heuristic security findings."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.http import HTTPRequest
from scapy.utils import PcapNgReader


@dataclass
class Finding:
    severity: str
    title: str
    summary: str
    evidence: str
    recommendation: str


@dataclass
class AnalysisResult:
    capture_path: str
    packet_count: int = 0
    total_bytes: int = 0
    start_time: float | None = None
    end_time: float | None = None
    protocol_packets: Counter[str] = field(default_factory=Counter)
    protocol_bytes: Counter[str] = field(default_factory=Counter)
    flows: dict[tuple[str, str, str, int, int], int] = field(default_factory=dict)
    io_bins: Counter[int] = field(default_factory=Counter)
    findings: list[Finding] = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.start_time is None or self.end_time is None:
            return 0.0
        return max(0.0, self.end_time - self.start_time)


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00\r\n ")
    return str(value).strip("\x00\r\n ") if value is not None else ""


def _protocol(packet: Any) -> str:
    if packet.haslayer(TCP):
        ports = {int(packet[TCP].sport), int(packet[TCP].dport)}
        if 80 in ports:
            return "HTTP"
        if 443 in ports or 8443 in ports:
            return "HTTPS/TLS"
        if 22 in ports:
            return "SSH"
        if 23 in ports:
            return "Telnet"
        if 21 in ports:
            return "FTP"
        if 25 in ports or 587 in ports:
            return "SMTP"
        return "TCP"
    if packet.haslayer(UDP):
        ports = {int(packet[UDP].sport), int(packet[UDP].dport)}
        if 53 in ports:
            return "DNS"
        if 67 in ports or 68 in ports:
            return "DHCP"
        return "UDP"
    return "Other"


def _endpoints(packet: Any) -> tuple[str, str]:
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return "unknown", "unknown"


def analyze_capture(capture_path: str | Path) -> AnalysisResult:
    """Read a pcapng file and return aggregated traffic and heuristic findings."""
    path = Path(capture_path)
    result = AnalysisResult(capture_path=str(path))
    port_sets: dict[tuple[str, str], set[int]] = defaultdict(set)
    udp_port_sets: dict[tuple[str, str], set[int]] = defaultdict(set)
    handshake_states: dict[tuple[str, int, str, int], tuple[bool, float]] = {}
    incomplete_by_source: Counter[str] = Counter()
    beacon_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    http_endpoints: Counter[tuple[str, str]] = Counter()
    suspicious_web: set[tuple[str, str]] = set()

    with PcapNgReader(str(path)) as reader:
        for packet in reader:
            timestamp = float(packet.time)
            size = len(packet)
            source, destination = _endpoints(packet)
            result.packet_count += 1
            result.total_bytes += size
            result.start_time = timestamp if result.start_time is None else min(result.start_time, timestamp)
            result.end_time = timestamp if result.end_time is None else max(result.end_time, timestamp)
            result.io_bins[int(timestamp)] += size

            protocol = _protocol(packet)
            result.protocol_packets[protocol] += 1
            result.protocol_bytes[protocol] += size

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                source_port, destination_port = int(tcp.sport), int(tcp.dport)
                flow = ("TCP", source, destination, source_port, destination_port)
                result.flows[flow] = result.flows.get(flow, 0) + size
                flags = int(tcp.flags)
                if flags & 0x02 and not flags & 0x10:
                    handshake_states[(source, source_port, destination, destination_port)] = (False, timestamp)
                    port_sets[(source, destination)].add(destination_port)
                elif flags & 0x12 == 0x12:
                    original = (destination, destination_port, source, source_port)
                    if original in handshake_states:
                        handshake_states[original] = (True, handshake_states[original][1])
                elif flags & 0x10 and not flags & 0x02:
                    original = (source, source_port, destination, destination_port)
                    state = handshake_states.get(original)
                    if state and state[0]:
                        del handshake_states[original]

                if source_port in {80, 8080, 8000} or destination_port in {80, 8080, 8000}:
                    request = packet.getlayer(HTTPRequest)
                    if request is not None:
                        host = _decode(getattr(request, "Host", b"")) or destination
                        uri = _decode(getattr(request, "Path", b"")) or "/"
                        http_endpoints[(host, uri)] += 1
                        if any(term in uri.lower() for term in ("/login", "/admin", "upload", "cmd=", "shell", "token")):
                            suspicious_web.add((host, uri))

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                source_port, destination_port = int(udp.sport), int(udp.dport)
                flow = ("UDP", source, destination, source_port, destination_port)
                result.flows[flow] = result.flows.get(flow, 0) + size
                if destination_port not in {53, 67, 68, 123, 5353}:
                    udp_port_sets[(source, destination)].add(destination_port)

            if protocol not in {"DNS", "DHCP"} and source != "unknown" and destination != "unknown":
                beacon_times[(source, destination)].append(timestamp)

    for (source, destination), ports in port_sets.items():
        sorted_ports = sorted(ports)
        longest_run = run_length = 0
        previous = None
        for port in sorted_ports:
            run_length = run_length + 1 if previous is not None and port == previous + 1 else 1
            longest_run = max(longest_run, run_length)
            previous = port
        if len(ports) >= 12:
            result.findings.append(Finding(
                "High" if len(ports) >= 30 or longest_run >= 10 else "Medium",
                "TCP port sweep",
                f"One host attempted connections to {len(ports)} TCP ports on a single destination.",
                f"{source} -> {destination}; {len(ports)} distinct destination ports, longest consecutive run {longest_run}.",
                "Confirm the source is an authorized scanner; otherwise investigate the host and restrict unnecessary access.",
            ))

    for (source, destination), ports in udp_port_sets.items():
        if len(ports) >= 15:
            result.findings.append(Finding(
                "Medium", "UDP port sweep",
                f"One host sent traffic to {len(ports)} distinct UDP destination ports.",
                f"{source} -> {destination}; {len(ports)} distinct destination ports observed.",
                "Check whether this is approved discovery activity and review the destination hosts for unexpected services.",
            ))

    for source, destination, source_port, destination_port in handshake_states:
        incomplete_by_source[source] += 1
    for source, count in incomplete_by_source.items():
        if count >= 5:
            result.findings.append(Finding(
                "High" if count >= 20 else "Medium", "Incomplete TCP handshakes",
                f"{count} TCP connection attempts from one host did not complete a captured handshake.",
                f"Source {source}; incomplete SYN attempts: {count}.",
                "Check for SYN scanning, packet loss, or a service outage; correlate with firewall and endpoint logs.",
            ))

    plaintext_bytes = result.protocol_bytes["HTTP"] + result.protocol_bytes["Telnet"] + result.protocol_bytes["FTP"]
    if result.protocol_packets["Telnet"] or (result.total_bytes and plaintext_bytes / result.total_bytes >= 0.15):
        plain_names = [name for name in ("HTTP", "Telnet", "FTP") if result.protocol_packets[name]]
        result.findings.append(Finding(
            "High" if result.protocol_packets["Telnet"] else "Medium",
            "Plaintext protocol exposure",
            "Cleartext application traffic may expose credentials or sensitive content to anyone able to observe the network.",
            f"Observed protocols: {', '.join(plain_names)}; {plaintext_bytes:,} bytes ({plaintext_bytes / max(result.total_bytes, 1):.1%} of captured bytes). "
            f"Secure SSH packets: {result.protocol_packets['SSH']:,}; HTTPS/TLS packets: {result.protocol_packets['HTTPS/TLS']:,}.",
            "Prefer HTTPS/TLS and SSH, and remove or isolate legacy cleartext services.",
        ))

    heavy_threshold = max(1_000_000, result.total_bytes * 0.25)
    for (transport, source, destination, source_port, destination_port), size in result.flows.items():
        if size >= heavy_threshold:
            result.findings.append(Finding(
                "Medium", "Large data transfer",
                f"A single {transport} flow carried {size:,} bytes, which may warrant an exfiltration review.",
                f"{source}:{source_port} -> {destination}:{destination_port}; {size:,} bytes ({size / max(result.total_bytes, 1):.1%} of capture).",
                "Validate the destination and business purpose, then compare transfer volume with endpoint and proxy logs.",
            ))

    for (source, destination), timestamps in beacon_times.items():
        unique_times = sorted(set(timestamps))
        if len(unique_times) < 7:
            continue
        intervals = [later - earlier for earlier, later in zip(unique_times, unique_times[1:])]
        average_interval = mean(intervals)
        variation = pstdev(intervals) / average_interval if average_interval else 1.0
        if 10 <= average_interval <= 3600 and variation <= 0.12:
            result.findings.append(Finding(
                "Medium", "Regular outbound beacon pattern",
                "Repeated traffic at unusually regular intervals can be consistent with automated command-and-control check-ins.",
                f"{source} -> {destination}; {len(unique_times)} packets, mean interval {average_interval:.1f}s, interval variation {variation:.1%}.",
                "Review the destination and owning process; correlate timing with DNS, proxy, and endpoint telemetry.",
            ))

    for (host, uri), count in sorted(http_endpoints.items()):
        severity = "Medium" if (host, uri) in suspicious_web else "Low"
        reason = "URI contains a sensitive-path keyword; verify whether the request was expected." if severity == "Medium" else "Unencrypted HTTP exposes request metadata and potentially content."
        result.findings.append(Finding(
            severity, "Unencrypted HTTP request",
            f"Observed HTTP request to {host}{uri} ({count} request{'s' if count != 1 else ''}).",
            f"Host: {host}; URI: {uri}; count: {count}. {reason}",
            "Confirm the endpoint is expected and migrate the service to HTTPS where possible.",
        ))

    if not result.findings:
        result.findings.append(Finding(
            "Info", "No configured heuristics triggered",
            "No anomaly matched the current offline checks.",
            "This does not establish that the capture is benign; encrypted, missing, or out-of-scope activity may not be visible.",
            "Review the protocol and flow summaries and correlate with endpoint or firewall telemetry.",
        ))
    return result
