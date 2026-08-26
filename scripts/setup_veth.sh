#!/usr/bin/env bash
set -e

ACTION="${1:-setup}"

VETH0="veth0"
VETH1="veth1"
IP0="10.10.10.1/24"
IP1="10.10.10.2/24"

if [ "$ACTION" = "setup" ]; then
    echo "[VETH] Creating virtual pair $VETH0 <--> $VETH1..."
    
    # Remove if existing
    ip link del "$VETH0" 2>/dev/null || true

    # Create veth pair
    ip link add "$VETH0" type veth peer name "$VETH1"

    # Configure IPs
    ip addr add "$IP0" dev "$VETH0"
    ip addr add "$IP1" dev "$VETH1"

    # Bring them up
    ip link set "$VETH0" up
    ip link set "$VETH1" up

    echo "[VETH] Interfaces created successfully!"
    echo "  $VETH0: $IP0 (MAC: $(cat /sys/class/net/$VETH0/address))"
    echo "  $VETH1: $IP1 (MAC: $(cat /sys/class/net/$VETH1/address))"
    echo ""
    echo "To test XDP BPF_TEST live frames injection on veth:"
    echo "  Terminal 1 (Listener/Capture):"
    echo "    sudo tcpdump -i $VETH1 -nnvvXX port 9999"
    echo "    # or: nc -u -l 10.10.10.2 9999"
    echo ""
    echo "  Terminal 2 (Sender):"
    echo "    sudo ./bin/xdp_ping -i $VETH0 -d 10.10.10.2 -m $(cat /sys/class/net/$VETH1/address) -p 9999"
elif [ "$ACTION" = "teardown" ]; then
    echo "[VETH] Removing $VETH0..."
    ip link del "$VETH0" 2>/dev/null || true
    echo "[VETH] Done."
else
    echo "Usage: $0 [setup|teardown]"
    exit 1
fi
