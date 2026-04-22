# One-Machine Penetration Test Writeup Template

Use this template for a single HTB, PG, lab, or OSCP-style target. It is designed to stay readable for a per-machine writeup while still covering the items emphasized in the attached OffSec OSCP exam report template: high-level summary, recommendations, methodology walkthrough, detailed reproduction steps, screenshots, sample code, and `local.txt` / `proof.txt` evidence where applicable.

This is intentionally a per-target template, not a full multi-host exam report. Use it as the individual machine section you would want to drop into a broader exam or professional report.

It is designed for two jobs:

1. Capture clean notes while testing.
2. Convert those notes into a concise final writeup without rewriting everything.

Delete sections you do not need. Keep raw notes short, preserve only useful evidence, and make the exploitation narrative reproducible enough that another reviewer could follow it without guessing.

---

## Report Metadata

| Field | Value |
|---|---|
| Platform | `<HTB / PG / Lab / Exam>` |
| Machine | `<name>` |
| Target | `<IP / hostname>` |
| OS | `<Linux / Windows / Unknown>` |
| Status | `<In Progress / Completed>` |
| Objective | `<user / root / SYSTEM / specific goal>` |
| Time Budget | `<optional>` |
| Report Audience | `<self / exam / client / internal>` |
| Screenshot Folder | `<screenshots/machine-name/>` |
| Loot Folder | `<loot/machine-name/>` |

## Scope And Constraints

- In-scope target(s):
- Allowed actions / rules of engagement:
- Assumed starting position:
- Tooling constraints:
- Notes on lab instability or resets:

## Assessment Snapshot

| Field | Value |
|---|---|
| Initial Access Vector | `<service / credential / vuln / misconfig>` |
| Privilege Escalation Vector | `<sudo / token privilege / service misconfig / kernel / credential reuse>` |
| Final Access | `<user / root / Administrator / SYSTEM>` |
| Overall Risk | `<Critical / High / Medium / Low>` |
| Primary Impact | `<RCE / credential theft / admin access / lateral movement potential>` |
| Confidence | `<Confirmed / Likely / Needs validation>` |

## OSCP Alignment Checklist

- High-level summary is present and non-technical enough to skim quickly.
- Methodology and step-by-step actions are documented in attack order.
- Each major issue includes explanation, reproduction, evidence, and fix guidance.
- Required proof artifacts are captured with `whoami` / `id`, host context, and `local.txt` or `proof.txt` when applicable.
- Screenshots are referenced at each major milestone.
- Any custom exploit code, edited payload, or modified script is included or referenced.

## At A Glance

- Highest-value target surface:
- Fastest likely foothold:
- Best current privesc lead:
- Biggest blocker:
- Next action if resuming later:

## Executive Summary

Briefly state:

- what was exposed
- what led to initial access
- what enabled privilege escalation
- what impact was demonstrated
- what should be fixed first

Use 4 to 6 sentences max.

## Recommendations

- `<highest-priority fix>`
- `<hardening or access-control improvement>`
- `<credential, patching, or segmentation action>`

## Attack Path

1. Recon identified `<exposed surface>`.
2. Testing confirmed `<weakness>`.
3. Initial access was obtained as `<user / context>`.
4. Post-exploitation enumeration revealed `<escalation condition>`.
5. Privilege escalation succeeded via `<technique>`.
6. Impact was proven by `<flag / command execution / data access / admin control>`.

## Key Artifacts

| Type | Value | Why It Matters |
|---|---|---|
| Credential |  |  |
| Hash / Secret / Token |  |  |
| Host / Domain / User |  |  |
| File / Path / Config |  |  |
| URL / Endpoint / Share |  |  |

## Attack Timeline

| Time | Phase | Outcome |
|---|---|---|
|  | Recon |  |

## Methodology Walkthrough

Use this as the report-ready narrative. Keep it concise, but make sure the order is complete enough for a reviewer to follow from recon to objective completion.

1. Information gathering: `<what was enumerated first and why>`
2. Service enumeration: `<what services or application behavior mattered>`
3. Penetration: `<how initial access was obtained>`
4. Privilege escalation: `<how elevated access was obtained, if applicable>`
5. Post-exploitation: `<what was accessed or demonstrated>`
6. House cleaning / cleanup: `<what was removed or not required>`

---

## Operator Log

Use this during the engagement. Keep entries short and decision-focused. If it does not change your next move, do not log it.

```md
### `<time>` - `<phase>`
- Action: `<what you did>`
- Result: `<what happened>`
- Evidence: `<command output / screenshot / loot file>`
- Assessment: `<why it mattered>`
- Next: `<next step>`
```

## Quick Command Journal

Use this only for commands worth keeping. Do not dump every command you ran. Prefer one command per line with a short note if needed.

```bash
# Recon
<command>

# Exploitation
<command>

# PrivEsc
<command>
```

## Screenshot Plan

- Recon screenshot: `<scan result / app landing page / share listing>`
- Initial access screenshot: `<shell, login, or code execution>`
- User proof screenshot: `<whoami + hostname + local.txt if applicable>`
- Privilege escalation screenshot: `<key enum result or exploitation step>`
- Final proof screenshot: `<whoami / id + hostname + proof.txt if applicable>`
- Optional impact screenshot: `<sensitive data, admin action, or control demonstrated>`

---

## Recon

### Service Summary

| Port | Service | Version | Observation | Priority |
|---|---|---|---|---|
|  |  |  |  | `<High / Medium / Low>` |

### Priority Targets

- Immediate hypotheses to test:
- Likely auth or trust weaknesses:
- Likely credential sources:
- Items to ignore unless stuck:

### Web / Application Notes

- Titles, redirects, virtual hosts, or interesting headers:
- Auth flows or exposed functionality:
- Interesting directories, files, parameters, or APIs:
- Uploads, injections, deserialization, template, or auth opportunities:

### Infrastructure Notes

- Users, groups, shares, domains, hostnames, or email patterns discovered:
- Trust boundaries or segmentation clues:
- Software versions worth checking:
- Dead ends worth preserving:

### Evidence

```text
<short nmap summary, web titles, headers, shares, banners, vhosts, endpoints, etc.>
```

### Screenshot Reference

- Recon screenshot file:

### Recon Exit Criteria

- Enough evidence exists to justify the next exploit attempt.
- Low-value enumeration paths have been deprioritized.
- The next 1 to 3 actions are clear.

---

## Initial Access

### What Was Found

- Weakness:
- Why it mattered:
- Preconditions:
- Access obtained:

### How It Was Exploited

1. `<step>`
2. `<step>`
3. `<step>`

### Step-By-Step Reproduction

Use this section for the exact OSCP-style sequence. Include concrete commands, URLs, credentials, payload names, and files if they were truly used.

1. `<enumeration step with command>`
2. `<validation step with output or observation>`
3. `<exploit step with payload or request>`
4. `<callback / shell catch / login confirmation>`

### Evidence

```bash
<minimum proof of foothold>
```

### Screenshot Reference

- Initial access screenshot file:
- User proof screenshot file:

### Reproduction Notes

- Required tools or inputs:
- Reliability / caveats:
- Cleanup considerations:
- What would have prevented this step:

### Access Details

- Shell / session type:
- Stability:
- File transfer method:
- Local admin rights: `<yes / no / unknown>`

### Sample Code / Payload

Use this only if you modified exploit code, a webshell, a macro, a PowerShell script, or a payload.

```text
File:
Purpose:
Changes made:
```

```code
<modified exploit snippet, payload fragment, or request body if relevant>
```

---

## Post-Exploitation Enumeration

### Session Context

- Current user:
- Hostname:
- Groups / privileges:
- Network reachability:
- Defensive controls noted:
- Session limitations:
- Available tooling on host:

### High-Value Enumeration Results

| Check | Result | Why It Mattered |
|---|---|---|
| Local privileges / `sudo -l` / token privileges |  |  |
| Credentials / secrets / configs |  |  |
| Scheduled tasks / cron / services |  |  |
| Writable paths / binaries / scripts |  |  |
| Running applications / internal services |  |  |
| Interesting files / backups / history |  |  |

### Escalation Decision

- Best path identified:
- Why it was prioritized:
- Alternatives ruled out:
- Required assumptions:

### Enumeration Exit Criteria

- A primary privesc path is selected.
- Fallback privesc paths are documented.
- Further enumeration is unlikely to produce a better option quickly.

### Post-Exploitation Notes

- Sensitive files reviewed:
- Credentials or trust relationships discovered:
- Pivoting value:
- Persistence used: `<none / temporary / exam-safe note>`

---

## Privilege Escalation

### What Was Found

- Weakness:
- Why it mattered:
- Required access:
- Result:

### How It Was Exploited

1. `<step>`
2. `<step>`
3. `<step>`

### Step-By-Step Reproduction

1. `<enumeration command or observation>`
2. `<manual validation of the weakness>`
3. `<exploit or abuse step>`
4. `<elevated shell or admin confirmation>`

### Evidence

```bash
<minimum proof of root / Administrator / SYSTEM>
```

### Screenshot Reference

- Privesc screenshot file:
- Final proof screenshot file:

### Reproduction Notes

- Preconditions:
- Reliability / caveats:
- Operational notes:
- What would have prevented this step:

### Final Access Context

- Final user / integrity level:
- Sensitive access demonstrated:
- Constraints still present after escalation:

### Sample Code / Payload

```text
File:
Purpose:
Changes made:
```

```code
<msi generation command, exploit patch, PowerShell fragment, edited config, or other relevant code>
```

---

## Findings

Document weaknesses as findings, not as a replay of every command used. Create one finding per materially distinct issue. For an OSCP-style machine writeup, these can stay brief as long as the exploitation and proof sections are complete.

### Finding: `<title>`

| Field | Value |
|---|---|
| Severity | `<Critical / High / Medium / Low / Info>` |
| Affected Asset | `<host / service / path / account>` |
| Category | `<RCE / weak credentials / misconfiguration / privilege escalation / exposed service>` |
| CWE / Mapping | `<optional>` |

**What was found**  
`<clear description of the weakness>`

**Why it mattered**  
`<practical attacker impact>`

**How it was proven**  
`<minimum evidence showing the issue was real and exploitable>`

**Screenshot evidence**  
`<screenshot file name(s) and what each proves>`

**How to reproduce**  
`<concise validation steps for another tester or reviewer>`

**Sample code or payload**  
`<reference modified exploit, request, shell, script, or note not applicable>`

**How to fix it**  
`<specific remediation, not generic patch advice>`

Copy this finding block only as needed.

## Finding Candidate Queue

- `<issue idea not yet promoted into a formal finding>`
- `<supporting weakness or defense gap>`

---

## Proof And Evidence

Keep this explicit and minimal. If a screenshot or command does not prove something important, leave it out.

- Initial foothold proof: `<whoami / shell / screenshot / session proof>`
- User-level objective proof: `<whoami / hostname / ipconfig or ifconfig / local.txt / screenshot>`
- Privileged access proof: `<id / whoami / hostname / admin group / root proof>`
- Privileged objective proof: `<proof.txt / root flag / admin-only access / screenshot>`
- Impact proof: `<what control, access, or exposure was demonstrated>`
- Evidence locations: `<screenshots/...>`, `<loot/...>`, `<notes/...>`

## Screenshot Index

| Screenshot | File | Shows |
|---|---|---|
| Recon |  |  |
| Initial access |  |  |
| User proof |  |  |
| PrivEsc |  |  |
| Final proof |  |  |

## Loot Inventory

| Item | Location | Sensitivity | Used For |
|---|---|---|---|
|  |  | `<Low / Medium / High>` |  |

## Reporting Notes

- Evidence that belongs in the final report:
- Evidence that should stay in private notes only:
- Anything that needs sanitizing before sharing:
- Anything copied from the target that should be quoted minimally:

---

## Remediation

### Priority Actions

- `<highest-value fix>`
- `<credential reset / service restriction / access control change>`
- `<hardening step that would break the attack path>`

### Validation

- `<how to confirm the issue is fixed>`
- `<how to confirm the full attack path no longer works>`

## Lessons Learned

- What signal was most useful:
- What was almost missed:
- What should be tested earlier next time:
- What made the attack path realistic:

## Cleanup

- Accounts created:
- Files dropped:
- Services changed:
- Persistence removed / not applicable:

---
