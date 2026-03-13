# Manual testing checklist

Use this after following `guides/DEPLOYMENT.md`.

## 1. Handshake + tunnel bring-up

Start the server:

```bash
sudo ./target/release/apt-edge serve --config /etc/adapt/server.toml
```

Start the client:

```bash
sudo ./target/release/apt-client connect --config ./adapt-client/client.toml
```

Expected result:

- the client establishes a session and creates its TUN interface
- the server creates its TUN interface and shows one active session

## 2. Validate the tunnel interfaces

### On the server

```bash
ip addr show aptsrv0
```

Expected:

- interface exists
- server tunnel IP is present, for example `10.77.0.1/24`

### On the client (Linux)

```bash
ip addr show apt0
```

### On the client (macOS)

```bash
ifconfig apt0 2>/dev/null || ifconfig | grep -A4 utun
```

Expected:

- a TUN/utun interface exists with the assigned client tunnel IP

## 3. Ping across the encrypted tunnel

From the client:

```bash
ping 10.77.0.1
```

Expected:

- replies from the server tunnel IP

## 4. Validate full-tunnel internet egress

If the server pushes `0.0.0.0/0` and NAT is enabled:

```bash
curl https://ifconfig.me
```

Expected:

- the reported public IP is the **server’s** public IP, not the client’s original IP

## 5. Validate route preservation to the VPN server

The runtime installs a direct route to the server before redirecting default traffic.

From the client, verify that the VPN session stays up while full-tunnel routing is active.

A simple check is to keep `ping 10.77.0.1` running while also browsing or curling through the tunnel.

## 6. Inspect server forwarding/NAT state

On the Linux server:

```bash
sysctl net.ipv4.ip_forward
sudo iptables -t nat -S | grep MASQUERADE
sudo iptables -S FORWARD
```

Expected:

- `net.ipv4.ip_forward = 1`
- a `MASQUERADE` rule for the tunnel subnet
- `FORWARD` accept rules for the tunnel interface

## 7. Packet inspection (optional)

On the server:

```bash
sudo tcpdump -ni any udp port 51820
sudo tcpdump -ni aptsrv0
```

Expected:

- UDP traffic on the listening port
- decrypted IP packets traversing the server TUN interface

## 8. Resume-ticket smoke test

1. Connect once.
2. Stop the client cleanly.
3. Reconnect using the same config and `state_path`.

Expected:

- the client still reconnects successfully
- the state file is preserved on disk

## 9. Common failure checks

If the client does not connect:

- confirm the server UDP port is reachable
- confirm `endpoint_id` matches on both sides
- confirm the client has the correct `shared-admission.key`
- confirm the client has the correct `server-static-public.key`
- confirm the server `[[peers]]` entry matches the client public key
- confirm both processes have the privileges needed to create TUN devices

If the tunnel comes up but internet access fails:

- verify `egress_interface` is correct
- verify NAT rules were applied
- verify the server itself can reach the internet
- verify the client received/pushed the expected default route
