# Nimbus VPN

A simple VPN using TUN devices, Diffie-Hellman key exchange (RFC 3526 Group 14), and ChaCha20-Poly1305 encryption. Supports macOS and Linux.

## Build

```bash
cargo build --release
```

The binary is at `target/release/nimbus`.

## Setup

### Prerequisites

Both server and client need:
- Root / sudo access (required for TUN device creation and route management)
- Linux: TUN module loaded (`sudo modprobe tun`, verify `/dev/net/tun` exists)
- macOS: no extra steps needed

### Server

**1. Open UDP port in firewall (e.g. AWS security group: inbound UDP 8080)**

**2. Start the server**
```bash
sudo ./target/release/nimbus server --port 8080
```

The server will:
- Create a TUN device with VPN IP `10.0.0.1`
- Enable IP forwarding via `sysctl`

**3. Set up NAT so client traffic can reach the internet** (optional, needed for full tunnel routing)
```bash
# Replace ens5 with your network interface (check with: ip link show)
sudo iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o ens5 -j ACCEPT
sudo iptables -A FORWARD -i ens5 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

---

### Client

**Start the client**
```bash
sudo ./target/release/nimbus client --address <server-ip> --port 8080 --local-port 9090
```

The client will:
- Create a TUN device with VPN IP `10.0.0.2`
- Perform a DH handshake with the server to establish a shared encryption key
- Route traffic to `10.0.0.1` through the tunnel

---

## Verify

**Ping the server through the tunnel**
```bash
ping 10.0.0.1
```

**Check tunnel traffic is encrypted on the wire**
```bash
# On server — should only see UDP, no plaintext ICMP
sudo tcpdump -i ens5 udp port 8080 -n

# On server — should see decrypted traffic here
sudo tcpdump -i tun0 -n
```

**Test internet routing through the VPN**
```bash
curl --interface tun0 https://checkip.amazonaws.com
# Should return the server's public IP
```

---

## VPN IPs

| Role   | TUN address | Peer      |
|--------|-------------|-----------|
| Server | 10.0.0.1    | 10.0.0.2  |
| Client | 10.0.0.2    | 10.0.0.1  |
