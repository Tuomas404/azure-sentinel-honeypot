#!/usr/bin/env bash
# Lets GitHub Actions deploy Sentinel rules without stored passwords (OIDC).
# Creates a managed identity in the lab resource group, trusts only this repo's
# main branch, and grants Microsoft Sentinel Contributor on the resource group.
# Usage: bash setup-ci.sh   (run after deploy.sh, then copy the printed values
#        to GitHub: Settings > Secrets and variables > Actions)
set -euo pipefail

SUB="${SUB:-Azure for Students}"
RG="${RG:-rg-honeypot}"
LOC="${LOC:-swedencentral}"
ID_NAME="${ID_NAME:-id-github-sentinel}"
# GitHub's OIDC subject contains the owner and repo IDs as well as the names.
# If the repo is renamed or recreated, copy the new subject from the login error.
GH_SUBJECT="${GH_SUBJECT:-repo:Tuomas404@224398163/azure-sentinel-honeypot@1422420825:ref:refs/heads/main}"

echo "== 1/3 Managed identity"
az identity create --subscription "$SUB" -g "$RG" -n "$ID_NAME" -l "$LOC" -o none

echo "== 2/3 Federated credential (trust GitHub Actions on main)"
az identity federated-credential create --subscription "$SUB" -g "$RG" \
  --identity-name "$ID_NAME" -n github-main \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "$GH_SUBJECT" \
  --audiences "api://AzureADTokenExchange" -o none

echo "== 3/3 Role: Microsoft Sentinel Contributor on the resource group"
PRINCIPAL=$(az identity show --subscription "$SUB" -g "$RG" -n "$ID_NAME" --query principalId -o tsv)
RGID=$(az group show --subscription "$SUB" -n "$RG" --query id -o tsv)
EXISTING=$(az role assignment list --subscription "$SUB" --assignee "$PRINCIPAL" \
  --role "Microsoft Sentinel Contributor" --scope "$RGID" --query "[].id" -o tsv)
if [ -z "$EXISTING" ]; then
  az role assignment create --subscription "$SUB" \
    --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
    --role "Microsoft Sentinel Contributor" --scope "$RGID" -o none
else
  echo "  already assigned"
fi

echo
echo "GitHub repository secrets:"
echo "  AZURE_CLIENT_ID=$(az identity show --subscription "$SUB" -g "$RG" -n "$ID_NAME" --query clientId -o tsv)"
echo "  AZURE_TENANT_ID=$(az account show --subscription "$SUB" --query tenantId -o tsv)"
echo "  AZURE_SUBSCRIPTION_ID=$(az account show --subscription "$SUB" --query id -o tsv)"
