#!/usr/bin/env bash
# Deploys the Sentinel honeypot lab end to end.
# Usage: bash deploy.sh                      (resource group rg-honeypot)
#        RG=rg-honeypot-test bash deploy.sh  (separate test copy)
set -euo pipefail
cd "$(dirname "$0")"

SUB="${SUB:-Azure for Students}"
RG="${RG:-rg-honeypot}"
LOC="${LOC:-swedencentral}"
VM="${VM:-vm-honeypot}"
NAME="${RG#rg-}"
LAW="law-${NAME}"
SIZE="${SIZE:-Standard_B2als_v2}"
RULE_ID="8f3c2b1a-4d5e-4f60-9a7b-1c2d3e4f5a6b"
API_SI="2024-03-01"
API_DCR="2022-06-01"

echo "== 1/8 Resource providers"
for ns in Microsoft.Compute Microsoft.Network Microsoft.OperationalInsights \
          Microsoft.OperationsManagement Microsoft.SecurityInsights Microsoft.Insights \
          Microsoft.DevTestLab Microsoft.Logic; do
  az provider register --subscription "$SUB" --namespace "$ns" --wait
done

echo "== 2/8 Resource group"
az group create --subscription "$SUB" -n "$RG" -l "$LOC" -o none

echo "== 3/8 VM (Trusted Launch, managed identity, auto-shutdown)"
IMAGE=$(az vm image list --subscription "$SUB" --publisher MicrosoftWindowsServer --offer WindowsServer \
  --sku 2025-datacenter-g2 --all --query "[-1].urn" -o tsv)
read -rs -p "VM admin password: " VMPASS; echo
az vm create --subscription "$SUB" -g "$RG" -n "$VM" --image "$IMAGE" --size "$SIZE" \
  --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true \
  --admin-username labadmin --admin-password "$VMPASS" \
  --public-ip-sku Standard --nsg-rule RDP --assign-identity -o none
unset VMPASS
az vm auto-shutdown --subscription "$SUB" -g "$RG" -n "$VM" --time 2000 -o none

echo "== 4/8 Log Analytics workspace"
az monitor log-analytics workspace create --subscription "$SUB" -g "$RG" -n "$LAW" -l "$LOC" -o none
WSID=$(az monitor log-analytics workspace show --subscription "$SUB" -g "$RG" -n "$LAW" --query id -o tsv)

echo "== 5/8 Microsoft Sentinel"
az rest --method put -o none \
  --url "https://management.azure.com${WSID}/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=${API_SI}" \
  --body '{"properties":{}}'

echo "== 6/8 Azure Monitor Agent"
az vm extension set --subscription "$SUB" -g "$RG" --vm-name "$VM" -o none \
  --name AzureMonitorWindowsAgent --publisher Microsoft.Azure.Monitor --enable-auto-upgrade true

echo "== 7/8 Data collection rule"
SUBID=$(az account show --subscription "$SUB" --query id -o tsv)
DCRID="/subscriptions/${SUBID}/resourceGroups/${RG}/providers/Microsoft.Insights/dataCollectionRules/dcr-${NAME}-security"
VMID=$(az vm show --subscription "$SUB" -g "$RG" -n "$VM" --query id -o tsv)
jq --arg ws "$WSID" --arg loc "$LOC" \
  '.location = $loc | .properties.destinations.logAnalytics[0].workspaceResourceId = $ws' \
  dcr/security-events.json > /tmp/dcr.json
az rest --method put -o none --url "https://management.azure.com${DCRID}?api-version=${API_DCR}" --body @/tmp/dcr.json
az rest --method put -o none \
  --url "https://management.azure.com${VMID}/providers/Microsoft.Insights/dataCollectionRuleAssociations/dcra-${NAME}?api-version=${API_DCR}" \
  --body "{\"properties\":{\"dataCollectionRuleId\":\"${DCRID}\"}}"

echo "== 8/8 Analytics rule"
az rest --method put -o none \
  --url "https://management.azure.com${WSID}/providers/Microsoft.SecurityInsights/alertRules/${RULE_ID}?api-version=${API_SI}" \
  --body @rules/rdp-bruteforce.json

echo "Done. Public IP: $(az vm show -d --subscription "$SUB" -g "$RG" -n "$VM" --query publicIps -o tsv)"
