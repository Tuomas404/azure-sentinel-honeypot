#!/usr/bin/env bash
# Usage: source env.sh
# No secrets here: password is asked at runtime, IDs are looked up from Azure.

SUB="Azure for Students"
RG="rg-honeypot"
LOC="swedencentral"
VM="vm-honeypot"
LAW="law-honeypot"

az account set --subscription "$SUB"
SUBID=$(az account show --subscription "$SUB" --query id -o tsv)
WSID=$(az monitor log-analytics workspace show --subscription "$SUB" -g "$RG" -n "$LAW" --query id -o tsv)
WSGUID=$(az monitor log-analytics workspace show --subscription "$SUB" -g "$RG" -n "$LAW" --query customerId -o tsv)

echo "Tilaus: $(az account show --query name -o tsv) | RG: $RG | Workspace: $LAW"
