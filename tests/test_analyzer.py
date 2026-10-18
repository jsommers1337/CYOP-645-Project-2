import tempfile
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest
from scapy.utils import PcapNgWriter

from analyzer import analyze_capture


class AnalyzeCaptureTests(unittest.TestCase):
    def analyze_packets(self, packets):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "test.pcapng"
            writer = PcapNgWriter(str(path))
            for packet in packets:
                writer.write(packet)
            writer.close()
            return analyze_capture(path)

    def test_detects_tcp_port_sweep_and_plaintext_http(self):
        packets = []
        for index, port in enumerate(range(4000, 4013)):
            packets.append(IP(src="10.0.0.8", dst="198.51.100.4") / TCP(sport=51000 + index, dport=port, flags="S"))
        request = IP(src="10.0.0.8", dst="198.51.100.4") / TCP(sport=52000, dport=80) / HTTP() / HTTPRequest(Host="example.test", Path="/login")
        packets.append(request)

        result = self.analyze_packets(packets)
        titles = {finding.title for finding in result.findings}

        self.assertEqual(result.packet_count, 14)
        self.assertIn("TCP port sweep", titles)
        self.assertIn("Plaintext protocol exposure", titles)
        http_finding = next(finding for finding in result.findings if finding.title == "Unencrypted HTTP request")
        self.assertIn("example.test", http_finding.evidence)
        self.assertIn("/login", http_finding.evidence)

    def test_detects_regular_beacon_intervals(self):
        packets = []
        for index in range(8):
            packet = IP(src="10.0.0.12", dst="203.0.113.9") / UDP(sport=53000, dport=9001)
            packet.time = 1_700_000_000 + index * 60
            packets.append(packet)

        result = self.analyze_packets(packets)

        self.assertTrue(any(finding.title == "Regular outbound beacon pattern" for finding in result.findings))

    def test_udp_port_sweep_is_scoped_to_a_destination(self):
        packets = []
        for index, port in enumerate(range(2000, 2008)):
            packets.append(IP(src="10.0.0.12", dst="198.51.100.2") / UDP(sport=53000 + index, dport=port))
            packets.append(IP(src="10.0.0.12", dst="198.51.100.3") / UDP(sport=54000 + index, dport=port))

        result = self.analyze_packets(packets)

        self.assertFalse(any(finding.title == "UDP port sweep" for finding in result.findings))

    def test_empty_capture_reports_no_heuristics(self):
        result = self.analyze_packets([])

        self.assertEqual(result.packet_count, 0)
        self.assertEqual(result.findings[0].title, "No configured heuristics triggered")


if __name__ == "__main__":
    unittest.main()
