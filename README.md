# CodeAlpha_BasicNetworkSniffer
A lightweight packet sniffer written in ''Python 3'' using ''Scapy'', designed for ''Windows'' systems with Npcap.   It captures and analyzes network packets in real time, showing IP addresses, ports, protocols, flags, and optional payloads — helping you learn how data flows through your network.

## Features

 Capture live network packets on Windows  
 Display source/destination IPs, MACs, protocols, and ports  
 Decode TCP, UDP, and ICMP headers  
 Optional hex+ASCII payload display  
 BPF-style filters (e.g., `tcp or udp`, `port 53`)  
 Save captured packets to `.pcap` for Wireshark analysis  
 Educational — great for learning networking and protocols  

---

## Requirements

1. **Windows 10 or 11**
2. **Npcap** (install in *WinPcap API-compatible mode*):  
   👉 [https://npcap.com/](https://npcap.com/)
3. **Python 3.9+**
4. Install dependencies:
   ```bash
   pip install scapy


| Command                                                       | Description                    |
| ------------------------------------------------------------- | ------------------------------ |
| `python windows_sniffer.py --list-ifaces`                     | Show all network interfaces    |
| `python windows_sniffer.py -i "Wi-Fi"`                        | Capture all packets on Wi-Fi   |
| `python windows_sniffer.py -i "Ethernet" -f "tcp"`            | Capture only TCP packets       |
| `python windows_sniffer.py -i "Ethernet" --show-hex -c 50`    | Show payloads for 50 packets   |
| `python windows_sniffer.py -i "Ethernet" --pcap capture.pcap` | Save packets to Wireshark PCAP |

Disclaimer

This project is intended for educational and ethical use only.
Do not use this tool to intercept or analyze traffic on networks you don’t own or have permission to monitor.
