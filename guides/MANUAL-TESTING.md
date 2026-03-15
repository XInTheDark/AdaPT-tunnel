# Manual testing checklist

Use this after following `guides/DEPLOYMENT.md`.

## 0. Optional automated QA pass

Before walking through the manual checklist, you can run the built-in client QA helper:

```bash
sudo ./target/release/apt-client service install
./target/release/apt-client test
```

It brings the tunnel up temporarily, runs tunnel ping checks plus DNS/public-egress/download checks when full-tunnel routing is active, and then disconnects automatically. The manual steps below are still useful when you want deeper carrier-specific validation or more targeted debugging.


## 1. Handshake + tunnel bring-up

Start the server:

```bash
sudo ./target/release/apt-edge start --config /etc/adapt/server.toml
```

Start the client:

```bash
./target/release/apt-client up
```

Expected result:

- the client establishes a session over `D1` or `D2` and creates its TUN interface
- the server creates its TUN interface and shows one active session

## 2. Validate the tunnel interfaces

### On the server

```bash
ip addr show aptsrv0
```

Expected:

- interface exists
- server tunnel IPv4 is present, for example `10.77.0.1/24`
- if IPv6 is enabled, the server tunnel IPv6 is also present, for example `fd77:77::1/64`

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

Expected:

- replies from the server tunnel IP

If IPv6 is enabled, also verify:

```bash
ping6 fd77:77::1
```

Expected:

- replies from the server tunnel IPv6

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

- on macOS, traffic to `1.1.1.1` should resolve to the `utun` interface when full-tunnel routing is active
- the reported public IP is the **server’s** public IP, not the client’s original IP

## 5. Validate pushed DNS behavior

If the server pushes DNS servers, verify that the client applied them while the tunnel is up.

On Linux:

```bash
resolvectl status
```

Expected:

- the tunnel interface shows the pushed DNS servers

On macOS:

```bash
scutil --dns | grep 'nameserver\[[0-9]\]'
```

Expected:

- the pushed DNS servers appear in the active resolver set while the tunnel is connected

If the client logs a warning about DNS automation instead, the tunnel should still work, but DNS may need to be set manually on that machine.

## 6. Validate route preservation to the VPN server

The runtime installs a direct route to the server before redirecting default traffic.

From the client, verify that the VPN session stays up while full-tunnel routing is active.

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
- a `MASQUERADE` rule for the tunnel subnet
- if IPv6 NAT66 is enabled, a matching `ip6tables` `MASQUERADE` rule for the IPv6 tunnel subnet
- `FORWARD` accept rules for the tunnel interface

## 8. Packet inspection (optional)

On the server:

```bash
sudo tcpdump -ni any 'udp port 51820 or tcp port 443'
sudo tcpdump -ni aptsrv0
```

Expected:

- UDP traffic on the `D1` listening port and optional UDP traffic on the `D2` QUIC port
- decrypted IP packets traversing the server TUN interface

## 9. D2 QUIC-datagram smoke test

If your server config includes `d2_bind` / `d2_public_endpoint`, validate `D2` directly:

```bash
./target/release/apt-client up --carrier d2
```

Expected:

- the client establishes a session successfully over `D2`
- the server logs a `D2` carrier session
- `ping 10.77.0.1` and the full-tunnel checks still work over that forced carrier

## 10. Resume-ticket smoke test

1. Connect once.
2. Stop the client cleanly.
3. Reconnect using the same config and `state_path`.

Expected:

- the client still reconnects successfully
- the state file is preserved on disk
- older state/config files are rewritten with newly added runtime fields as they are loaded

## 11. Common failure checks

If the client does not connect:

- confirm the server UDP port is reachable for `D1`
- confirm the server UDP QUIC port is reachable for `D2` when enabled
- confirm `endpoint_id` matches on both sides
- confirm the client has the correct `.aptbundle` generated for that peer
- confirm the bundle was copied intact and not mixed up with another client's bundle
- confirm the server `[[peers]]` entry matches the client public key
- confirm `d2_server_addr` / `d2_public_endpoint` are correct if you are forcing or expecting `D2`
- confirm the client's `d2_server_certificate` matches the server's current `D2` certificate
- confirm you did not pin the client to the wrong carrier with `--carrier`
- confirm both processes have the privileges needed to create TUN devices

If the tunnel comes up but internet access fails:

- verify `egress_interface` is correct
- verify NAT rules were applied
- verify the server itself can reach the internet
- verify the client received/pushed the expected default route
- verify the pushed DNS servers were applied, or set DNS manually if local automation was unavailable
