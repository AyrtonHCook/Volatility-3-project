# Case Study — Windows Memory Forensics (Volatility 3)

**Date:** 05-06-2025 
**Author:** Ayrton Cook  

---

## Executive summary

I analysed a Windows 10 memory image (`memdump.dmp`) on REMnux using Volatility 3. I recovered a terminated `powershell.exe` (PID 4296), extracted a Base64 `-EncodedCommand` blob, decoded it offline, and found it created a marker file and used `Start-Sleep -Seconds 600`. The behaviour is consistent with delayed-execution sandbox-evasion. The decoded payload in this lab was benign, but the pattern is relevant for triage and detection.

---

## Background & scope

**Scenario:** Post-incident forensic triage of a Windows 10 host memory capture. The objective was to determine whether PowerShell was used to execute obfuscated commands from memory and, if so, recover and analyse the payload.

**Scope:** Volatile memory only (no disk analysis). The analysis focused on process listings, command-lines, string recovery, payload extraction, and safe offline decoding.

**Assurance:** All decoding was performed offline on an isolated analysis VM. Raw artefacts and screenshots are retained under `/artefacts/` and `/screenshots/`.

---

## Environment & acquisition

- **Analysis host:** REMnux (VMware Workstation Pro)  
- **Memory image:** `memdump.dmp` (2.4 GB, captured using DumpIt)  
- **Tools:** Volatility 3
- **Isolation:** All decoding was performed on the analysis VM  

---

## Tools used

* Volatility 3 (`vol3`) — core plugins: `psscan`, `pstree`, `cmdline`, `strings`  
* `strings` (GNU binutils) with UTF-16LE option (`-el`)  
* `base64`, `iconv` / Python for safe decoding  
* `sha256sum` for artefact integrity checks  

All analysis steps are reproducible with the commands below.

---

## Analysis steps (reproducible commands)

```bash
# recover terminated processes
vol3 -f memdump.dmp windows.psscan

# process tree for context
vol3 -f memdump.dmp windows.pstree

# dump command-line arguments (if present)
vol3 -f memdump.dmp windows.cmdline

# search for EncodedCommand strings in memory (UTF-16LE)
strings -el memdump.dmp | grep -i EncodedCommand > decoded_strings.txt

# extract the base64 blob (manual or scripted) and save to file: encoded_blob.b64
# decode safely offline (example using python)
python3 - <<'PY'
import base64
blob = open('encoded_blob.b64','rb').read()
decoded = base64.b64decode(blob)
open('artefacts/decoded_payload.txt','wb').write(decoded)
PY

# convert UTF-16LE to UTF-8 if necessary
iconv -f UTF-16LE -t UTF-8 artefacts/decoded_payload.txt > artefacts/decoded_payload_utf8.txt

# compute sha256 for verification
sha256sum artefacts/decoded_payload_utf8.txt
```

> Note: extraction of the encoded blob may require manual trimming of surrounding characters depending on how the string was recovered. I trimmed surrounding quotes during extraction in this analysis — see `/docs/extraction_notes.md` for the helper script.

---

## Key evidence

1. **Process recovery:** `psscan` recovered a terminated `powershell.exe` with PID **4296**.  
   (Screenshot: `/screenshots/02-psscan_pid4296.png`)  

2. **Command-line discovery:** `strings -el` revealed `-EncodedCommand` usage and a long Base64 blob present in memory.  
   (Screenshot: `/screenshots/05-strings-encodedcommand.png`)  

3. **Decoded payload (trimmed):** The decoded content created a marker file and included `Start-Sleep -Seconds 600`.  
   (Screenshot: `/screenshots/06-decoded_payload_snippet.png`; artefact: `/artefacts/decoded_payload.txt`, sha256: `REPLACE_WITH_SHA256`)  

**Trimmed decoded payload (example):**

```powershell
New-Item -Path C:\temp\ps_test.txt -ItemType File -Force
Start-Sleep -Seconds 600
# (payload trimmed for brevity)
```

---

## Findings & interpretation

* A terminated PowerShell process (PID 4296) executed with a Base64 `-EncodedCommand` argument. This shows that encoded commands were loaded into PowerShell and persisted in memory after process termination.  

* The decoded payload performed benign operations in this lab instance (wrote `ps_test.txt`) and used `Start-Sleep -Seconds 600`. Long sleep timers are a recognised sandbox-evasion technique (delayed execution) and align with MITRE ATT&CK T1497.001.  

* The presence of encoded commands (T1027) with PowerShell execution (T1059.001) is a common attacker TTP combination — worth flagging for further investigation on disk, network, and persistence artefacts.  

---

## MITRE ATT&CK mapping (detailed)

| Tactic          | Technique                                    | Evidence                                                                                       |
|-----------------|----------------------------------------------|------------------------------------------------------------------------------------------------|
| Execution       | **T1059.001 — PowerShell**                   | Encoded PowerShell observed in command-line recovered from memory                              |
| Defence Evasion | **T1027 — Obfuscated / Encoded Commands**    | Base64-encoded payload recovered and decoded offline                                           |
| Defence Evasion | **T1497.001 — Sandbox Evasion (Sleep)**      | `Start-Sleep -Seconds 600` observed in decoded payload — consistent with delayed execution     |
| Analyst method  | **T1057 — Process Discovery**                | `psscan` used by analyst to recover terminated process (PowerShell PID 4296)                   |

---

## Limitations & caveats

* Memory analysis cannot prove actions performed after process exit (e.g. network callbacks or file changes) without disk or network artefacts.  
* Encoding extraction is sensitive to string boundaries; partial blobs can result in decoding errors. Document offsets and keep raw captures to verify.  
* Long sleep usage can also appear in benign automation — corroboration is required before drawing conclusions.  

---

## Recommendations

1. Correlate memory findings with disk and network captures from the same host/time window.  
2. Hunt in endpoint logs and SIEM for `-EncodedCommand` and `Start-Sleep` usage.  
3. Add memory-based scans for common encoded-command prefixes and log long sleep timers.  
4. Preserve `/artefacts/decoded_payload.txt` and record its sha256 so reviewers can reproduce decoding.  

---

## Artefacts & screenshots

* `/artefacts/decoded_payload.txt` — decoded payload (sha256: `REPLACE_WITH_SHA256`)  
* `/screenshots/02-psscan_pid4296.png` — psscan output showing PID 4296  
* `/screenshots/03-pstree_pid4296.png` — process tree context  
* `/screenshots/05-strings-encodedcommand.png` — strings output showing `-EncodedCommand`  
* `/screenshots/06-decoded_payload_snippet.png` — decoded payload snippet (trimmed)  

---

## Reproducibility notes

* All commands above were executed on REMnux with Volatility 3 (`vol3` entry point).  
* Exact plugin paths and versions should be recorded in the repo for full reproducibility.  
* Include `/artefacts/decoded_payload.txt` and its SHA256 in the repo so others can verify decoding steps.  

---

## Appendix — example trimmed outputs

**Example psscan output (trimmed)**

```
4296    4308    powershell.exe    ...    2025-09-30 23:17:52.000000    N/A
```

**Example strings grep output (trimmed)**

```
... -EncodedCommand VwByAGkAdABlAC0A... (Base64 blob) ...
```

**Decoded payload (trimmed)**

```powershell
New-Item -Path C:\temp\ps_test.txt -ItemType File -Force
Start-Sleep -Seconds 600
# additional script content trimmed
```

---

## References

* Volatility 3 project: [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)  
* MITRE ATT&CK: [https://attack.mitre.org/](https://attack.mitre.org/)  

---

*End of case study.*
