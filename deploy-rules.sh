#!/usr/bin/env bash
# Deploys every analytics rule in rules/ to the Sentinel workspace.
# Usage: bash deploy-rules.sh   (or RG=rg-honeypot-test bash deploy-rules.sh)
set -euo pipefail
cd "$(dirname "$0")"

SUB="${SUB:-Azure for Students}"
RG="${RG:-rg-honeypot}"
LAW="law-${RG#rg-}"
API_SI="2024-03-01"

WSID=$(az monitor log-analytics workspace show --subscription "$SUB" -g "$RG" -n "$LAW" --query id -o tsv)

for f in rules/*.json; do
  RID=$(jq -er .ruleId "$f")
  jq 'del(.ruleId)' "$f" > /tmp/rule.json
  az rest --method put -o none \
    --url "https://management.azure.com${WSID}/providers/Microsoft.SecurityInsights/alertRules/${RID}?api-version=${API_SI}" \
    --body @/tmp/rule.json
  echo "  deployed: $(jq -r .properties.displayName "$f")"
done
