#!/bin/bash

MODULE="skx_dram_decode_addr.ko"
MOD_NAME="skx_dram_decode_addr"
LOGFILE="decode_results.log"
DEFAULT_NUM=10

# === INPUT ===
NUM_ADDRESSES=${1:-$DEFAULT_NUM}
echo "Decoding $NUM_ADDRESSES random physical addresses..."
echo "===========================" > "$LOGFILE"

# === CHECKS ===
if [[ ! -f $MODULE ]]; then
    echo "Kernel module $MODULE not found in current directory"
    exit 1
fi

# Pre-warm sudo permissions
echo "🔐 You may be prompted for your password..."
sudo -v || exit 1

# === MAIN LOOP ===
for ((i = 1; i <= NUM_ADDRESSES; i++)); do
    PHYS_ADDR=$(printf "0x%016x" $(( RANDOM | (RANDOM << 16) | ((RANDOM & 0xFF) << 32) )))
    echo "[$i/$NUM_ADDRESSES] Testing address $PHYS_ADDR"

    # Insert module
    if ! sudo insmod "$MODULE" phys_addr=$PHYS_ADDR 2>/dev/null; then
        echo "⚠️ Failed to insert module for address $PHYS_ADDR" | tee -a "$LOGFILE"
        continue
    fi

    sleep 0.1

    # Get and filter dmesg output
    OUTPUT=$(sudo dmesg | tail -n 20 | grep -F '[skx_decode]')
    echo "$OUTPUT" | tee -a "$LOGFILE"

    # Remove the module
    sudo rmmod "$MOD_NAME" 2>/dev/null
    sleep 0.1
done

echo "Done. Results saved to $LOGFILE"
