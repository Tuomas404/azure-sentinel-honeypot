#!/usr/bin/env bash
# Deletes the whole lab. Usage: RG=rg-honeypot-test bash teardown.sh
set -euo pipefail
SUB="${SUB:-Azure for Students}"
RG="${RG:-rg-honeypot}"
read -r -p "Delete resource group '$RG' and EVERYTHING in it? Type its name to confirm: " ANSWER
[ "$ANSWER" = "$RG" ] || { echo "Cancelled."; exit 1; }
az group delete --subscription "$SUB" -n "$RG" --yes --no-wait
echo "Deletion started for $RG."
