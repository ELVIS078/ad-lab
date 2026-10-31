# T1566.001 — Phishing: Spearphishing Attachment (Macro)

## Objective

Simulate the opening move of a LockBit-style intrusion: a victim opens a
malicious Office attachment, its macro fires on `Document_Open`, and
spawns a child process from `WINWORD.EXE` — the classic "Office app
spawns an unexpected child process" pattern that nearly every EDR and
most public Sigma rules key off.

This is a **benign simulation**, modeled on the same approach used by
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)'s
T1566.001 tests: the macro does not download, persist, or exfiltrate
anything. It only spawns a harmless child process so the lab generates
the *real* process-creation telemetry that a genuine payload would
produce, which is what the detection rule actually needs to be tested
against.

## Prerequisites

- `client01` up and domain-joined (see repo root `README.md`)
- Sysmon + Wazuh agent installed (`ansible/playbooks/site.yml`)
- Macros enabled in the test Office install on `client01` (lab-only —
  never do this on a real endpoint)

## Attacker narrative

1. Victim receives `invoice_Q3.docm` (simulated — delivery itself is out
   of scope here; this TTP starts at "user double-clicks the attachment").
2. Document opens, macro auto-runs via `Document_Open()`.
3. Macro spawns `cmd.exe` → `powershell.exe` as a child of `WINWORD.EXE`,
   mirroring how real droppers stage a second-stage payload.
4. Sysmon Event ID 1 (process creation) captures the parent/child
   relationship — this is the signal the Sigma rule below detects.

## How to run

1. Copy `execute.ps1` onto `client01` (simulates what the macro would do
   once it fires — see script header for why it's split this way).
2. Run it as the logged-in test user (not as admin — matches how a real
   phishing victim would trigger it):
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File execute.ps1
   ```
3. Confirm Sysmon logged it: Event Viewer → Applications and Services
   Logs → Microsoft → Windows → Sysmon → Operational, filter Event ID 1.
4. Start the detection stack (`detection-stack/wazuh-single-node`) if not
   already running, confirm the agent shipped the event, and that the
   Wazuh rule in `detection/` fires an alert.
5. Screenshot the alert in the Wazuh dashboard, redact hostnames/IPs if
   sharing publicly, save to `evidence/`.

## Cleanup

```powershell
# No persistence was created, nothing to remove except the dropped script.
Remove-Item .\execute.ps1 -ErrorAction SilentlyContinue
```

## Files

- `execute.ps1` — benign process-spawn simulation (see script comments)
- `../../detections/sigma/T1566.001-office-child-process.yml` — detection rule
- `../../detections/wazuh/T1566.001-phishing-macro.xml` — Wazuh custom rule derived from the Sigma logic
- `../../detections/queries/T1566.001-phishing-macro.md` — deployment steps + KQL/SPL equivalents
- `../../screenshots/` — evidence from a real run (add your own; gitignored raw logs)
