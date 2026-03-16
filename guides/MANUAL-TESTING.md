# Manual testing checklist

Use this after following `guides/DEPLOYMENT.md`.

## 0. Optional automated QA pass

```bash
sudo ./target/release/apt-client service install
./target/release/apt-client test
```

This brings the tunnel up temporarily, runs tunnel ping checks plus DNS/public-egress/download checks when full-tunnel routing is active, and then disconnects automatically.

## 1. H2 session + tunnel bring-up

Start the server:

```bash
sudo ./target/release/apt-edge start --config /etc/adapt/server.toml
```

Start the client:

```bash
./target/release/apt-client up
```

Expected result:

- the client establishes an H2 session and creates its TUN interface
- the server creates its TUN interface and shows one active session

## 2. Validate the tunnel interfaces

### On the server

```bash
ip addr show aptsrv0
```

Expected:

- interface exists
- server tunnel IPv4 is present, for example `10.77.0.1/24`
- if IPv6 is enabled, the server tunnel IPv6 is also present

### On the client (Linux)

```bash
ip addr show apt0
```

### On the client (macOS)

```bash
ifconfig | grep -A4 utun
```

Expected:

- a TUN/utun interface exists with the assigned client tunnel IPv4
- if IPv6 is enabled, the assigned client tunnel IPv6 is also present

## 3. Ping across the encrypted tunnel

From the client:

```bash
ping 10.77.0.1
```

If IPv6 is enabled, also verify:

```bash
ping6 fd77:77::1
```

## 4. Validate full-tunnel internet egress

If the server pushes `0.0.0.0/0` and/or `::/0` and forwarding/NAT are enabled:

On Linux:

```bash
ip route get 1.1.1.1
ip -6 route get 2606:4700:4700::1111
curl https://ifconfig.me
curl -6 https://ifconfig.me
```

On macOS:

```bash
route -n get 1.1.1.1
route -n get -inet6 2606:4700:4700::1111
curl https://ifconfig.me
curl -6 https://ifconfig.me
```

Expected:

- full-tunnel traffic resolves to the TUN/`utun` interface
- the reported public IP is the server's public IP, not the client's original IP

## 5. Validate pushed DNS behavior

On Linux:

```bash
resolvectl status
```

On macOS:

```bash
scutil --dns | grep 'nameserver\[[0-9]\]'
```

Expected:

- the pushed DNS servers appear while the tunnel is connected

## 6. Validate route preservation to the VPN server

The client installs a direct route to the server before redirecting default traffic.
A simple check is to keep `ping 10.77.0.1` running while also browsing or curling through the tunnel.

## 7. Inspect server forwarding/NAT state

On the Linux server:

```bash
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
sudo iptables -t nat -S | grep MASQUERADE
sudo ip6tables -t nat -S | grep MASQUERADE
sudo iptables -S FORWARD
sudo ip6tables -S FORWARD
```

Expected:

- `net.ipv4.ip_forward = 1`
- if IPv6 is enabled, `net.ipv6.conf.all.forwarding = 1`
- NAT and FORWARD rules exist for the tunnel interface/subnets

## 8. Packet inspection (optional)

On the server:

```bash
sudo tcpdump -ni any 'tcp port 443'
sudo tcpdump -ni aptsrv0
```

Expected:

- public H2/TLS traffic on the configured TCP port
- decrypted IP packets traversing the server TUN interface

## 9. Resume-ticket smoke test

1. Connect once.
2. Stop the client cleanly.
3. Reconnect using the same config and `state_path`.

Expected:

- the client reconnects successfully
- the state file is preserved on disk
- older state/config files are rewritten with newly added runtime fields as they are loaded

## 10. Common failure checks

If the client does not connect:

- confirm the server TCP port is reachable
- confirm `public_endpoint`, `authority`, and `server_name` are correct
- confirm the client's `server_certificate` or `server_roots` matches the server trust model
- confirm `endpoint_id` matches on both sides
- confirm the client has the correct `.aptbundle`
- confirm the server `[[peers]]` entry matches the client public key
- confirm both processes have the privileges needed to create TUN devices

If the tunnel comes up but internet access fails:

- verify `egress_interface` is correct
- verify NAT rules were applied
- verify the server itself can reach the internet
- verify the client received the expected pushed routes
- verify the pushed DNS servers were applied, or set DNS manually if local automation was unavailable
