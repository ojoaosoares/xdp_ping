# xdp_ping

High-speed UDP/Ping packet generator using **eBPF/XDP** and the `bpf_prog_test_run_opts` syscall with **Live Frames** mode (`BPF_F_TEST_XDP_LIVE_FRAMES`).

---

## 🎯 Objective

Enable testing, validation, and benchmarking of the Linux `BPF_PROG_RUN` (`bpf_test_run`) packet injection mechanism without requiring external drivers or kernel modules.

---

## 🏗️ Building

### Requirements

* `clang` ($\ge$ 14)
* `bpftool`
* `libbpf-dev`
* `libelf-dev`
* `zlib1g-dev`

To build everything:

```bash
make
```

The binary will be generated at:

```text
bin/xdp_ping
```

---

## 🚀 Testing

### Mode 1: Testing with Virtual Interfaces (`veth`) — *Recommended (Zero Hardware)*

Linux `veth` interfaces provide native support for `BPF_F_TEST_XDP_LIVE_FRAMES` on kernels $\ge$ 5.18.

1. **Create the `veth0 <-> veth1` pair:**

   ```bash
   make setup-veth
   ```

2. **Terminal 1 (Receiver / Capture):**

   ```bash
   sudo tcpdump -i veth1 -nnvvXX 'udp port 9999'
   ```

   *(Alternatively, receive the packets with Netcat:)*

   ```bash
   nc -u -l 10.10.10.2 9999
   ```

3. **Terminal 2 (XDP Injector):**

   ```bash
   sudo ./bin/xdp_ping -i veth0 -d 10.10.10.2 -p 9999 -c 5
   ```

4. **Remove the virtual interfaces after testing:**

   ```bash
   make teardown-veth
   ```

---

### Mode 2: Testing on a Physical Interface (`enp1s0np1` / Fiber Optic)

```bash
# Standard ICMP Echo Ping (similar to the ping command):
sudo ./bin/xdp_ping -i enp1s0np1 -d 192.168.0.2 -c 10

# Or use UDP mode on port 9999:
sudo ./bin/xdp_ping -i enp1s0np1 -d 192.168.0.2 -u -p 9999 -c 10
```

---

## ⚙️ CLI Options

| Option        | Description                                   | Default                                          |
| :------------ | :-------------------------------------------- | :----------------------------------------------- |
| `-i <ifname>` | Network interface name                        | `enp1s0np1`                                      |
| `-d <ip>`     | Destination IPv4 address                      | `192.168.0.2`                                    |
| `-s <ip>`     | Source IPv4 address                           | Auto-detected from the interface                 |
| `-m <mac>`    | Destination MAC address                       | Automatically resolved via ARP (`/proc/net/arp`) |
| `-u`          | Use UDP instead of the default ICMP Echo Ping | ICMP Echo Ping                                   |
| `-p <port>`   | UDP destination port (only with `-u`)         | `9999`                                           |
| `-c <count>`  | Number of packets (`0` = infinite)            | `10`                                             |
| `-r <repeat>` | Number of repetitions per `test_run` call     | `1`                                              |
| `-t <ms>`     | Interval between transmissions in ms          | `1000`                                           |
| `-b <msg>`    | Custom payload message (UDP mode)             | `"PING from XDP BPF_TEST"`                       |
| `-h`          | Display the help menu                         | -                                                |

---

## 🔬 How It Works

1. **Kernel XDP (`src/xdp_ping.bpf.c`):**

   * XDP program attached in **DRIVER / NATIVE** mode (`XDP_FLAGS_DRV_MODE`).
   * Returns `XDP_TX` to reflect and transmit packets directly through the network driver's TX queue.

2. **Userspace (`src/xdp_ping.c`):**

   * Automatically resolves the destination MAC address from the system ARP table.
   * Attaches the BPF program to the network interface in **DRIVER** mode using `bpf_xdp_attach` with `XDP_FLAGS_DRV_MODE`, and verifies the attachment using `bpf_xdp_query_id`.
   * Constructs a complete frame equivalent to a standard Linux `ping` packet (Ethernet + IPv4 + ICMP Echo Request + Timestamp + Payload).
   * Injects the frames into the XDP hook through `bpf_prog_test_run_opts` with the `BPF_F_TEST_XDP_LIVE_FRAMES` flag.
   * Cleanly detaches the XDP program when exiting using `bpf_xdp_detach`.
