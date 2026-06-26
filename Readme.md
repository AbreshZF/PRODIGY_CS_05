# PacketAnalyzer — Deep Packet Inspection Utility

PacketAnalyzer is a Python-based network packet capture and inspection tool built on top of **Scapy**. It provides structured, readable output for analyzing network traffic in real time, including protocol headers, connection metadata, and payload previews.

It is designed for **educational use, network debugging, and security research in authorized environments only**.

---

## ⚠️ Legal Notice

This tool is intended strictly for:

- Authorized network diagnostics
- Educational cybersecurity research
- Systems you own or have explicit permission to monitor

Unauthorized interception or monitoring of network traffic may violate local laws and regulations. Use responsibly.

---

## Features

- Real-time packet sniffing using Scapy
- Supports interface-based capture (Wi-Fi, Ethernet, etc.)
- BPF (Berkeley Packet Filter) support
- Protocol detection (TCP, UDP, ICMP)
- Source/destination IP and port extraction
- TCP flag decoding
- Hex + ASCII payload inspection
- Packet counting limit option
- Optional file logging
- Clean structured terminal output

---

## Requirements

- Python 3.10+
- Scapy

```bash
pip install scapy
```

On Linux/macOS, you may also need:

```bash
sudo apt install tcpdump
```

---

## Installation

Clone or download the project:

```bash
git clone https://github.com/AbreshZF/PRODIGY_CS_05/packet-analyzer.git

cd PRODIGY_CS_05
```

---

## Usage

Run with elevated privileges (required for packet sniffing):

### Basic capture

```bash
sudo python packet_analyzer.py -i wlan0
```

### Capture HTTP traffic (port-based filter)

```bash
sudo python packet_analyzer.py -i wlan0 -f "tcp port 80"
```

### Capture HTTPS traffic with limit

```bash
sudo python packet_analyzer.py -i wlan0 -f "tcp port 443" -c 50
```

### Capture DNS traffic

```bash
sudo python packet_analyzer.py -i wlan0 -f "udp port 53"
```

### Save output to log file

```bash
sudo python packet_analyzer.py -i wlan0 --log packets.log
```

---

## CLI Arguments

| Argument | Description |
|----------|-------------|
| -i, --interface | Network interface to sniff on (required) |
| -f, --filter | BPF filter expression (e.g. "tcp port 80") |
| -c, --count | Number of packets to capture (0 = unlimited) |
| --log | Save output to a log file |

---

## BPF Filter Examples

| Filter | Description |
|--------|-------------|
| tcp port 80 | HTTP traffic |
| tcp port 443 | HTTPS traffic |
| udp port 53 | DNS queries |
| icmp | Ping traffic |
| host 192.168.1.xx | Traffic to/from specific host |

---

## Output Example


══════════════════════════════════════════════════════════════
Packet # 12 | 17:52:31.421 | TCP
══════════════════════════════════════════════════════════════
Src : 192.168.1.x Ports : 51544 → 80
Dst : 93.184.216.xx
TTL : 64 Length : 60 bytes Flags : SYN
Payload snippet:
00000000 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a |GET / HTTP/1.1..|


---

## Project Structure

```bash

packet-analyzer.py
README.md
```

---

## Known Limitations

- Requires root/administrator privileges
- BPF filters must use valid tcpdump syntax (e.g., `tcp port 80`, not `http`)
- Does not reassemble TCP streams
- Does not decrypt HTTPS traffic
- Payload preview is limited to first 64 bytes

---

## Future Improvements

- HTTP request parsing and reconstruction
- DNS domain extraction
- PCAP export support
- GUI dashboard for live traffic visualization
- Filter alias system (e.g., `http → tcp port 80`)
- Session/flow tracking

---

## Author

Developed for educational cybersecurity and network analysis purposes.

---

## License

MIT License
