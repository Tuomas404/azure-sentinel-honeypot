# Azure Sentinel Honeypot

Internet-exposed Windows Server in Azure, monitored with Microsoft Sentinel.
Built to practise detection engineering and SOC workflows (SC-200 topics):
two custom detection rules, both validated with controlled tests, and one real
internet brute-force attack detected, investigated and closed. Rules are managed
as code and deployed to Sentinel by GitHub Actions, with no stored credentials.

## Architecture

```mermaid
flowchart LR
  A[Internet] -->|RDP 3389| VM[Windows Server 2025<br/>Trusted Launch]
  VM -->|Security log| AMA[Azure Monitor Agent]
  AMA -->|Data Collection Rule| LAW[(Log Analytics)]
  LAW --> S[Microsoft Sentinel]
  S -->|Analytics rules T1110| I[Incidents]
```

## What's in this repo

| File | Purpose |
|---|---|
| `deploy.sh` | Builds the whole lab end to end with Azure CLI |
| `deploy-rules.sh` | Deploys every rule in `rules/` to Sentinel |
| `.github/workflows/deploy-rules.yml` | Validates and deploys rules on every push to `rules/` |
| `setup-ci.sh` | Creates the Azure identity GitHub Actions logs in with (OIDC) |
| `teardown.sh` | Deletes the lab (asks for confirmation) |
| `dcr/security-events.json` | Data Collection Rule: Windows Security log to Log Analytics |
| `rules/rdp-bruteforce.json` | Rule 1: fast brute force |
| `rules/rdp-lowandslow.json` | Rule 2: low-and-slow brute force |
| `env.sh` | Session variables for Azure Cloud Shell |

## Detection rules

Both rules map the source IP as an entity and group alerts from the same IP into one incident.

| | Rule 1: Fast brute force | Rule 2: Low-and-slow |
|---|---|---|
| Logic | ≥ 10 failed logons (4625) from one IP in 1 h | ≥ 20 in 24 h, spread over ≥ 3 hours, < 10 in any hour |
| Runs | Every hour, over the last hour | Every 6 hours, over the last 24 hours |
| MITRE ATT&CK | T1110 Brute Force | T1110 Brute Force |

Rule 2 is designed to catch attackers who stay under Rule 1's hourly threshold,
and it excludes fast attacks so the same activity does not create two incidents.

```kql
// Rule 2
SecurityEvent
| where EventID == 4625 and IpAddress != "-"
| summarize HourlyAttempts = count() by IpAddress, Hour = bin(TimeGenerated, 1h)
| summarize Attempts = sum(HourlyAttempts), ActiveHours = dcount(Hour),
            MaxPerHour = max(HourlyAttempts) by IpAddress
| where Attempts >= 20 and ActiveHours >= 3 and MaxPerHour < 10
```

## Validation

**Test 1, fast brute force (2026-10-17):** 10 failed RDP logons from my own IP within an hour.
Logs showed 12 × EventID 4625 and 1 × EventID 4740 (account locked out after 10 attempts).
Rule 1 created an incident, closed as *Benign Positive – suspicious but expected*.

<img width="1602" height="848" alt="Bruteforce Incident Open" src="https://github.com/user-attachments/assets/fd066b66-af2d-45b8-a49e-0bc1dc616f7c" />
<img width="1604" height="842" alt="Bruteforce Incident Closed" src="https://github.com/user-attachments/assets/ed3d1be2-3760-47cb-a18a-63429372c669" />

**Test 2, low-and-slow (2026-10-18):** 3 × 7 failed logons in separate hours (max 7 per hour).
Rule 2 created an incident and Rule 1 correctly stayed silent. Closed as *Benign Positive*.

<img width="1324" height="787" alt="Low-and-slow-open" src="https://github.com/user-attachments/assets/f71a3e9f-1109-4cfc-a407-dc0c337fb4c3" />
<img width="1329" height="793" alt="Low-and-slow-closed" src="https://github.com/user-attachments/assets/46d68bc3-2a59-46e6-a72c-247eff2dbf33" />


## First real attack (2026-10-17)

| | |
|---|---|
| Activity | 81 failed-logon events (EventID 4625) from one IP, 15:59–19:58 UTC, up to 21 per hour |
| IP geolocation | India (geolocation shows where the IP is, not who the attacker is) |
| Accounts tried | `Administrator`, `Admin`: neither exists on the host |
| Successful remote logons | None (no EventID 4624 logon type 3 or 10 from remote IPs in 3 days) |
| Outcome | No compromise. Activity ended when the VM's nightly auto-shutdown ran |
| Classification | *True Positive – suspicious activity* |

Rule 1 created one incident per hourly run (4 incidents for one attacker).
Fix: enabled alert grouping by entity, so repeated alerts from one IP join a single incident.

<img width="1330" height="789" alt="India Bruteforce Closed" src="https://github.com/user-attachments/assets/6377fb31-1551-4aa1-9b93-4a00e9739fcd" />


A few other IPs produced 1–2 failed-logon events each (scanners), below both thresholds by design.

## CI/CD: detection as code

```mermaid
flowchart LR
  D[Edit rules/*.json] -->|git push| GH[GitHub Actions]
  GH --> V{Validate JSON}
  V -->|invalid| X[Stop: nothing deployed]
  V -->|ok| L[Azure login with OIDC]
  L --> R[deploy-rules.sh]
  R --> S[Microsoft Sentinel]
```

- **Trigger:** push to `main` that changes `rules/`, `deploy-rules.sh` or the workflow. Can also be run by hand.
- **Validation:** every rule file must have `ruleId`, `kind`, `displayName` and `query`, or the job stops before touching Azure.
- **No stored passwords:** GitHub gets a short-lived token, and Azure trusts it only for this repo's `main` branch (federated credential on a managed identity).
- **Least privilege:** the identity has *Microsoft Sentinel Contributor* on the lab resource group only. It can edit rules but cannot change the VM, networking or permissions.
- **Tested end to end (2026-10-18):** changed Rule 1's description in Git, and the new text and modification time appeared in Sentinel without any manual step.

## Reproducibility

The full lab was rebuilt from scratch in a separate resource group with `deploy.sh`,
verified (resources, Trusted Launch, analytics rule) and torn down with `teardown.sh`.

```bash
git clone https://github.com/Tuomas404/azure-sentinel-honeypot.git
cd azure-sentinel-honeypot
bash deploy.sh        # prompts for VM admin password
bash setup-ci.sh      # identity for GitHub Actions, prints values for repo secrets
bash deploy-rules.sh  # manual rule deploy (CI does this on push)
bash teardown.sh      # deletes everything, including the CI identity
```

## Lessons learned

- **Non-default admin name works:** the real attacker only tried `Administrator` and `Admin`, so password guessing never reached the real account.
- **Duplicate incidents:** an hourly rule without grouping turned one attacker into four incidents. Grouping by entity fixed it.
- **Geolocation is not attribution:** attack traffic often comes from rented servers, VPNs or compromised hosts.
- **Tests interfere with each other:** a 24 h rule still "sees" yesterday's fast test, so tests must be scheduled outside each other's windows.
- **Events are not attempts:** 10 human attempts produced 12 failed-logon events. Thresholds must account for this.
- **Account lockout trade-off:** lockout stops password guessing but lets anyone who knows the username lock it (denial of service).
- **Wrong default subscription:** Azure CLI defaulted to a different production subscription linked to my student account. Every command now pins `--subscription`.
- **Missing resource providers:** registration errors appeared step by step; all providers are now registered at the start of `deploy.sh`.
- **OIDC subject format:** the first Actions login failed because GitHub's token subject now contains the owner and repo IDs (`repo:Owner@id/repo@id:...`), not just the names. IDs cannot be reused if a repo is deleted and recreated, which blocks a name-takeover attack. The error message showed the exact subject to trust.
- **Least privilege has gaps to plan for:** *Microsoft Sentinel Contributor* can edit rules but cannot read the Log Analytics workspace resource itself, so the workflow passes the workspace ID instead of looking it up.
- **Line endings:** shell scripts edited on Windows can get CRLF line endings that break Bash on Linux runners. `.gitattributes` forces LF for `*.sh`.
- **Capacity and deprecation:** `Standard_B2s` was unavailable in Sweden Central and the `Win2022Datacenter` image alias is scheduled for deprecation, so the lab uses `Standard_B2als_v2` and Windows Server 2025 Gen2.

## Cost control

Budget alert, nightly auto-shutdown, Sentinel 31-day free trial, and `teardown.sh` to delete everything.

## Next steps

- Automation rule to auto-close incidents from known test IPs
- Bicep version of `deploy.sh`
