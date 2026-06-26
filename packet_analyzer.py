"""
=============================================================================
  PacketAnalyzer — Deep Packet Inspection Utility
=============================================================================
  PURPOSE:  Authorized network debugging and educational study of packet
            structures. Use this tool to understand how traffic flows across
            an interface, inspect protocol headers, and capture raw payloads.

  AUTHORIZATION REQUIREMENT:
            This tool MUST be run with elevated privileges:
              Linux/macOS : sudo python packet_analyzer.py [options]
              Windows     : Run terminal as Administrator

            Only capture traffic on networks you own or have explicit written
            permission to monitor. Unauthorized interception of network
            traffic is illegal in most jurisdictions.

  USAGE EXAMPLES:
            # Capture all traffic on eth0
            sudo python packet_analyzer.py -i eth0

            # Capture only HTTP traffic
            sudo python packet_analyzer.py -i eth0 -f "tcp port 80"

            # Capture HTTPS traffic, limit to 50 packets, log to file
            sudo python packet_analyzer.py -i eth0 -f "tcp port 443" -c 50 --log packets.log

            # Capture DNS queries
            sudo python packet_analyzer.py -i eth0 -f "udp port 53"
=============================================================================
"""

import argparse
import logging
import sys
import textwrap
from datetime import datetime

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw,
        sniff, conf
    )
    from scapy.layers.dns import DNS
except ImportError:
    print("[FATAL] scapy is not installed. Run: pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

def configure_logging(log_file: str | None = None) -> logging.Logger:
    """Configure root logger with console (and optional file) handlers."""
    logger = logging.getLogger("PacketAnalyzer")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# PacketAnalyzer
# ---------------------------------------------------------------------------

class PacketAnalyzer:
    """
    Wraps scapy's sniff() with structured packet inspection and reporting.

    Separates capture configuration (interface, BPF filter, packet count)
    from the per-packet processing logic so each concern is easy to extend
    or unit-test independently.
    """

    PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}
    SEPARATOR = "─" * 72
    PAYLOAD_SNIPPET_BYTES = 64

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "",
        packet_count: int = 0,
        logger: logging.Logger | None = None,
    ):
        self.interface    = interface
        self.bpf_filter   = bpf_filter
        self.packet_count = packet_count          # 0 = unlimited
        self.logger       = logger or logging.getLogger("PacketAnalyzer")
        self._captured    = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin packet capture. Blocks until count is reached or Ctrl+C."""
        self._print_banner()
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                count=self.packet_count,
                prn=self._process_packet,
                store=False,          # don't accumulate in RAM
            )
        except KeyboardInterrupt:
            self._shutdown()
        except PermissionError:
            self.logger.error(
                "Permission denied — re-run with sudo / administrator rights."
            )
            sys.exit(1)

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _process_packet(self, packet) -> None:
        """Callback invoked by scapy for every captured packet."""
        if not packet.haslayer(IP):
            return  # skip non-IP frames (ARP, etc.) for this report

        self._captured += 1
        record = self._extract_fields(packet)
        self._log_record(record)

    def _extract_fields(self, packet) -> dict:
        """Pull the fields we care about from a scapy packet object."""
        ip_layer = packet[IP]

        proto_num  = ip_layer.proto
        proto_name = self.PROTO_MAP.get(proto_num, f"PROTO-{proto_num}")

        src_port = dst_port = None
        flags    = None

        if packet.haslayer(TCP):
            tcp        = packet[TCP]
            src_port   = tcp.sport
            dst_port   = tcp.dport
            flags      = self._decode_tcp_flags(tcp.flags)
        elif packet.haslayer(UDP):
            udp      = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport

        payload_snippet = self._extract_payload(packet)

        return {
            "index":    self._captured,
            "ts":       datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip":   ip_layer.src,
            "dst_ip":   ip_layer.dst,
            "proto":    proto_name,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl":      ip_layer.ttl,
            "length":   ip_layer.len,
            "flags":    flags,
            "payload":  payload_snippet,
        }

    def _extract_payload(self, packet) -> str:
        """
        Return a hex + ASCII side-by-side snippet of the raw payload,
        capped at PAYLOAD_SNIPPET_BYTES bytes for readability.
        """
        if not packet.haslayer(Raw):
            return "<no payload>"

        raw_bytes = bytes(packet[Raw].load)[: self.PAYLOAD_SNIPPET_BYTES]
        return self._hex_dump(raw_bytes)

    # ------------------------------------------------------------------
    # Output formatting
    # ------------------------------------------------------------------

    def _log_record(self, r: dict) -> None:
        """Emit a structured log entry for one captured packet."""
        port_info = ""
        if r["src_port"] is not None:
            port_info = f"  Ports : {r['src_port']} → {r['dst_port']}"

        flag_info = f"  Flags : {r['flags']}" if r["flags"] else ""

        header = (
            f"\n{self.SEPARATOR}\n"
            f"  Packet #{r['index']:>5}  |  {r['ts']}  |  {r['proto']}\n"
            f"{self.SEPARATOR}\n"
            f"  Src   : {r['src_ip']}{port_info}\n"
            f"  Dst   : {r['dst_ip']}"
        )

        meta = f"\n  TTL   : {r['ttl']}    Length : {r['length']} bytes{flag_info}"

        payload_block = textwrap.indent(r["payload"], prefix="    ")
        payload_label = "\n  Payload snippet:\n" + payload_block

        self.logger.info(header + meta + payload_label)

    def _print_banner(self) -> None:
        filter_display = f'"{self.bpf_filter}"' if self.bpf_filter else "none"
        limit_display  = str(self.packet_count) if self.packet_count else "unlimited"

        banner = (
            f"\n{'═' * 72}\n"
            f"  PacketAnalyzer  |  interface: {self.interface}\n"
            f"  BPF filter      : {filter_display}\n"
            f"  Packet limit    : {limit_display}\n"
            f"  Press Ctrl+C to stop.\n"
            f"{'═' * 72}"
        )
        self.logger.info(banner)

    def _shutdown(self) -> None:
        self.logger.info(
            f"\nCapture stopped by user. Total packets analysed: {self._captured}"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_tcp_flags(flags) -> str:
        """Convert scapy TCP flags bitmask to a human-readable string."""
        flag_chars = {
            "F": "FIN", "S": "SYN", "R": "RST",
            "P": "PSH", "A": "ACK", "U": "URG",
            "E": "ECE", "C": "CWR",
        }
        active = [label for char, label in flag_chars.items() if char in str(flags)]
        return "|".join(active) if active else "—"

    @staticmethod
    def _hex_dump(data: bytes) -> str:
        """
        Render bytes as a classic hex + printable-ASCII side-by-side dump.

        Example output (16 bytes per row):
          00000000  48 65 6c 6c 6f 2c 20 57  6f 72 6c 64 21 0a 00 00  |Hello, World!...|
        """
        if not data:
            return "<empty>"

        lines  = []
        width  = 16

        for offset in range(0, len(data), width):
            chunk     = data[offset: offset + width]
            hex_part  = " ".join(f"{b:02x}" for b in chunk)
            # pad so the ASCII column is always aligned
            hex_part  = f"{hex_part:<{width * 3 - 1}}"
            ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PacketAnalyzer — authorized deep packet inspection utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            BPF filter examples:
              tcp port 80          — HTTP traffic only
              tcp port 443         — HTTPS traffic only
              udp port 53          — DNS queries
              host 192.168.1.10    — traffic to/from a specific host
              icmp                 — ping / ICMP only
        """),
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        metavar="IFACE",
        help="Network interface to sniff on (e.g. eth0, en0, wlan0)",
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        metavar="BPF",
        help="Optional Berkeley Packet Filter expression",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        metavar="N",
        help="Stop after capturing N packets (default: unlimited)",
    )
    parser.add_argument(
        "--log",
        metavar="FILE",
        default=None,
        help="Also write output to a log file",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args   = parser.parse_args()

    logger   = configure_logging(log_file=args.log)
    analyzer = PacketAnalyzer(
        interface=args.interface,
        bpf_filter=args.filter,
        packet_count=args.count,
        logger=logger,
    )
    analyzer.start()


if __name__ == "__main__":
    main()
