---
name: network_analysis
description: Network traffic analysis — Wireshark filters, tcpdump, protocol RE, C2 detection, TLS inspection, packet forensics
---

# Network Traffic Analysis

## Capture

```bash
# tcpdump
tcpdump -i eth0 -w capture.pcap
tcpdump -i any -w capture.pcap                          # all interfaces
tcpdump -i eth0 'tcp port 80 or tcp port 443' -w web.pcap
tcpdump -i eth0 host 1.2.3.4 -w target.pcap
tcpdump -i eth0 'tcp and (port 4444 or port 8080)' -w c2.pcap
tcpdump -i eth0 -n -A 'tcp port 80'                     # print ASCII

# Write only first 100 bytes per packet (header only):
tcpdump -i eth0 -s 100 -w headers.pcap

# Rotate files (1MB each):
tcpdump -i eth0 -C 1 -w /tmp/cap -W 10
```

## Wireshark Filters

```wireshark
# HTTP
http
http.request
http.response.code == 200
http.request.uri contains "/api/"
http.request.method == "POST"

# DNS
dns
dns.qry.name contains "telegram"
dns.qry.name matches ".*\.onion"

# TCP
tcp.flags.syn == 1 and tcp.flags.ack == 0   # SYN (connection attempts)
tcp.flags.reset == 1                          # RST (connection refused/reset)
tcp.stream eq 5                               # follow TCP stream 5

# TLS
tls
tls.handshake.type == 1   # ClientHello (reveals SNI)
tls.record.content_type == 23  # Application data

# Specific host
ip.addr == 1.2.3.4
ip.src == 10.0.0.1
ip.dst == 8.8.8.8

# Find large transfers (possible data exfil)
tcp.len > 10000

# Combining filters
ip.addr == 1.2.3.4 and http.request

# Follow stream
# Right-click packet → Follow → TCP Stream
```

## Protocol Analysis

### HTTP/API Traffic

```bash
# Extract HTTP hosts from pcap
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u

# Extract all HTTP bodies (POST data)
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data

# Find all User-Agents
tshark -r capture.pcap -Y "http.request" -T fields -e http.user_agent | sort | uniq -c | sort -rn
```

### DNS Analysis

```bash
# All DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort -u

# Suspicious long DNS names (DNS tunneling)
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | \
  awk 'length($0) > 50' | sort -u

# DNS TXT records (data exfil channel)
tshark -r capture.pcap -Y "dns.qry.type == 16" -T fields -e dns.qry.name -e dns.txt

# Detect DNS C2 pattern: many unique subdomains of same domain
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | \
  grep "\.malware\.com$" | wc -l
```

### WebSocket Traffic

```bash
# WebSocket handshake
tshark -r capture.pcap -Y "websocket"
tshark -r capture.pcap -Y "http.upgrade == websocket" -T fields -e http.host

# WebSocket data frames
tshark -r capture.pcap -Y "websocket.payload" -T fields -e websocket.payload
```

## TLS Inspection

### With MITM Proxy (mitmproxy)

```bash
# Start mitmproxy
mitmproxy --listen-host 0.0.0.0 --listen-port 8080

# Or for transparent proxy:
mitmproxy --mode transparent --listen-port 8080

# Redirect traffic:
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-port 8080

# Export flows to HAR:
mitmdump -r flows.pcap -w flows.har --set flow_detail=3
```

### With SSLKEYLOGFILE (Chrome/Firefox)

```bash
# On the target machine:
export SSLKEYLOGFILE=/tmp/ssl_keys.log
google-chrome &    # or firefox
# After capture:

# Load in Wireshark:
# Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
# → /tmp/ssl_keys.log
# Now all TLS traffic is decrypted inline
```

### HTTPS via Burp Suite

```
Target → Scope → Include in scope: target.com
Proxy → Intercept is on
→ Configure browser to use 127.0.0.1:8080
→ Install Burp CA cert in browser
```

## C2 Detection Patterns

```python
import re
import subprocess

def analyze_pcap(pcap_file):
    """Extract C2 indicators from pcap."""
    
    # All unique IPs with port
    result = subprocess.run(
        ['tshark', '-r', pcap_file, '-T', 'fields', '-e', 'ip.dst', '-e', 'tcp.dstport'],
        capture_output=True, text=True
    )
    
    connections = {}
    for line in result.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) == 2 and parts[0] and parts[1]:
            ip, port = parts
            key = f"{ip}:{port}"
            connections[key] = connections.get(key, 0) + 1
    
    # High-frequency connections = beaconing
    beacons = {k: v for k, v in connections.items() if v > 50}
    
    # Unusual ports
    unusual = {k: v for k, v in connections.items() 
               if int(k.split(':')[-1]) not in [80, 443, 22, 53, 25, 587]}
    
    return {'beacons': beacons, 'unusual_ports': unusual}
```

| C2 Pattern | Indicator | Wireshark Filter |
|------------|-----------|-----------------|
| HTTP beaconing | Same URL every N seconds | `http.request.uri` repeated |
| DNS tunneling | Long subdomain names | `dns.qry.name` length > 50 |
| ICMP tunneling | Large ICMP payloads | `icmp.data_len > 8` |
| WebSocket C2 | Persistent WS to external IP | `websocket and not ip.dst == 10.0.0.0/8` |
| Telegram C2 | Connections to `api.telegram.org` | `dns.qry.name == "api.telegram.org"` |
| Domain fronting | Host: differs from SNI | TLS SNI ≠ HTTP Host header |

## Packet Forensics (CTF)

```bash
# Follow all TCP streams and dump to files
tshark -r challenge.pcap --export-objects http,/tmp/http_objects/

# Extract files from pcap (Wireshark GUI):
# File → Export Objects → HTTP (or SMB)

# Find all files in network traffic:
binwalk -e --dd='.*' capture.pcap

# ICMP data extraction:
tshark -r capture.pcap -Y "icmp.type==8" -T fields -e data.data | \
  tr -d '\n' | xxd -r -p

# Look for flag pattern in traffic:
strings capture.pcap | grep -i "flag{\|CTF{\|picoCTF{"
tshark -r capture.pcap -x | strings | grep -i "flag{"

# USB HID analysis (keyboard input)
tshark -r usb.pcap -Y 'usb.transfer_type == 0x01' -T fields -e usb.capdata
# Decode HID keycodes: python3 hid_decode.py keycodes.txt
```

## Traffic Generation for Testing

```python
import socket, time, struct

# Send raw TCP data to test IDS/firewall
def send_test_payload(host, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(payload)
    response = s.recv(4096)
    s.close()
    return response

# Simulate beaconing pattern
def beacon(host, port, interval=60):
    while True:
        try:
            r = send_test_payload(host, port, b"GET /beacon HTTP/1.0\r\n\r\n")
        except:
            pass
        time.sleep(interval)
```

## Quick Reference

```bash
# tshark one-liners:
tshark -r pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null | head
tshark -r pcap -q -z conv,tcp          # TCP conversations summary
tshark -r pcap -q -z io,stat,1         # throughput per second
tshark -r pcap -q -z endpoints,ip      # all IP endpoints
tshark -r pcap -q -z http,tree         # HTTP method/response tree

# Merge multiple pcaps
mergecap -w merged.pcap cap1.pcap cap2.pcap

# Edit/anonymize pcap
bittwiste -I input.pcap -O output.pcap -T ip -s 10.0.0.1

# Convert pcap to JSON (for scripting)
tshark -r capture.pcap -T json > capture.json
```
