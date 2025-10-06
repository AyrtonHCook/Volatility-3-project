# Windows Memory Forensics: Volatility 3

**Summary:**
This project was part of my ongoing cybersecurity learning and covers memory forensics using Volatility 3.
I examined a Windows 10 memory image (`memdump.dmp`) to find and decode an obfuscated PowerShell `-EncodedCommand`.
After decoding the Base64 payload offline, I discovered a harmless script that created a small text file and paused for ten minutes.
Although simple, this behaviour resembles typical sandbox evasion techniques used by real attackers.

---

## Goal

The aim was to simulate a practical memory forensics scenario: a system suspected of running suspicious PowerShell activity.
I wanted to learn how to extract evidence directly from a memory image and understand the purpose of the encoded data.

---

## Skills Demonstrated

* Memory forensics using **Volatility 3**
* Process and command-line analysis (`psscan`, `pstree`, `cmdline`)
* String extraction and Base64 decoding (UTF-16LE)
* Offline decoding and secure handling of evidence
* MITRE ATT&CK technique mapping
* Structured technical reporting with reproducible steps

---

## Environment and Setup

| Component             | Details                              |
| --------------------- | ------------------------------------ |
| Host                  | REMnux VM (VMware Workstation)       |
| Tool                  | Volatility 3 v2.7.0                  |
| Target Image          | `memdump.dmp` (Windows 10 x64)       |
| Working Directory     | `~/projects/volatility3-repo`        |
| Artefacts Directory   | `/artefacts/`                        |
| Screenshots Directory | `/screenshots/`                      |

SHA-256 checksums (for integrity):

```
artefacts/07-decoded-payload_utf8.txt → a9da4a8811b27c5e0677d10509e4dd8165f43637671a24f32fedd9e063ca1003
```

---

## Quick Reproduction

```bash
cd ~/projects/volatility3-repo
IMG="memdump.dmp"
OUT="artefacts"
mkdir -p "$OUT" screenshots

# Tool & environment validation
vol3 -f "$IMG" windows.info > "$OUT/01-tool-check.txt"

# Process discovery
vol3 -f "$IMG" windows.psscan > "$OUT/02-psscan.txt"
vol3 -f "$IMG" windows.pstree > "$OUT/03-pstree.txt"

# Command-line inspection
vol3 -f "$IMG" windows.cmdline > "$OUT/04-cmdline.txt"

# UTF-16LE string sweep to locate EncodedCommand
strings -a -el "$IMG" | egrep -i 'encodedcommand|-enc\b|FromBase64String|IEX' > "$OUT/05-strings-utf16-hits.txt"

# Extract and decode Base64 blob
grep -oE "[A-Za-z0-9+/=]{40,}" "$OUT/05-strings-utf16-hits.txt" | head -n 1 > "$OUT/06-encoded-command.b64"
python3 - <<'PY'
import base64, pathlib
payload = base64.b64decode(pathlib.Path("$OUT/06-encoded-command.b64").read_text().strip())
decoded = payload.decode('utf-16le')
pathlib.Path("$OUT/07-decoded-payload_utf8.txt").write_text(decoded)
PY
```

---

## Findings

* `psscan` recovered a terminated **powershell.exe** process (PID 4296) that `pslist` missed.
* `pstree` confirmed it was part of a legitimate process hierarchy.
* The `cmdline` output didn’t show any suspicious arguments, which prompted further inspection.
* A UTF-16LE `strings` sweep revealed a Base64-encoded command stored in memory.
* After decoding it offline, the script turned out to create `C:\temp\ps_test.txt` and use a long `Start-Sleep` delay.

**Decoded payload (trimmed):**

```powershell
Write-Output "DFIR TEST RUN" | Out-File C:\Temp\ps_test.txt -Encoding UTF8
Start-Sleep -Seconds 600
```

Even though it was harmless, the pattern was very similar to what analysts would see when malware tries to delay execution to evade sandboxes.

---

## Results Summary

| Evidence                                     | Description                                       |
| -------------------------------------------- | ------------------------------------------------- |
| `artefacts/01-tool-check.txt`                | Volatility 3 framework information and plugins    |
| `artefacts/02-psscan.txt`                    | Terminated process list (PID 4296)                |
| `artefacts/03-pstree.txt`                    | Process tree confirming parent-child relationship |
| `artefacts/04-cmdline.txt`                   | Command-line output with executable path          |
| `artefacts/05-strings-utf16-hits.txt`        | Encoded PowerShell command discovered in memory   |
| `artefacts/06-encoded-command.b64`           | Sanitized Base64 blob                             |
| `artefacts/07-decoded-payload_utf8.txt`      | Decoded PowerShell payload                        |
| `screenshots/02-psscan_pid4296.png`          | Evidence of process recovery                      |
| `screenshots/03-pstree_pid4296.png`          | Process lineage visual                            |
| `screenshots/05-strings-encodedcommand.png`  | Encoded command found in memory                   |
| `screenshots/06-decoded_payload_snippet.png` | Decoded script snippet                            |

---

## MITRE ATT&CK Mapping

| Tactic          | Technique (ID)                              | Evidence or Notes                                 |
| --------------- | ------------------------------------------- | ------------------------------------------------- |
| Execution       | T1059.001 PowerShell                        | Encoded PowerShell in memory                      |
| Defense Evasion | T1027 Obfuscated or Encoded Commands        | Base64-encoded payload                            |
| Defense Evasion | T1497.001 Virtualization or Sandbox Evasion | Long Start-Sleep delay                            |
| Discovery       | T1057 Process Discovery                     | Hidden PowerShell process recovered with `psscan` |

---

## Lessons Learned

This was my first full memory analysis from start to finish using Volatility 3.
Some lessons that stood out:

* Always check for terminated processes using `psscan`, not just `pslist`.
* PowerShell artifacts are often UTF-16LE, so the correct `strings` encoding flag is essential.
* Volatility 2 and 3 can coexist, so confirming the correct binary avoids plugin errors.
* Writing clear, reproducible notes after each step saves a lot of time later when documenting.

---

## Key Takeaway

Memory analysis can uncover hidden or terminated processes that still contain valuable traces of attacker activity.
Even simple encoded commands can reveal intent once decoded safely offline.

---

## Case Study

A more detailed walkthrough with command outputs and screenshots is available in:
[`docs/volatility-case-study.md`](docs/volatility-case-study.md)

---

## Safe Handling

All work was performed offline inside an isolated REMnux virtual machine.
No payloads were executed, and every artefact was hashed with SHA-256 for verification.

---

**Author:** Ayrton Cook
**Degree:** BSc Computer Science (Cybersecurity Pathway), University of East Anglia
**GitHub:** [AyrtonHCook](https://github.com/AyrtonHCook)
