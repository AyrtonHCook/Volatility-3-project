# Windows Memory Forensics: Volatility 3 Analysis

## Project Overview
For this project I used [Volatility 3](https://github.com/volatilityfoundation/volatility3) on REMnux to investigate a Windows 10 memory dump.  
The aim was to simulate a DFIR workflow: identify suspicious processes, recover command-line arguments, extract encoded payloads, and decode them safely.  
This helped me practice memory forensics, artifact hunting, and presenting findings in a structured way — skills directly relevant to SOC and incident response roles.

---

## Setup
**Environment**
- Host: REMnux VM with Volatility 3 Framework 2.7.0
- Image: Windows 10 memory dump (`memdump.dmp`)
- Target: `powershell.exe` (PID 4296)

**Tools**
- Volatility 3 (plugins: `psscan`, `pstree`, `cmdline`, `strings`)
- `strings` for UTF-16LE scanning
- `base64` + `iconv` for safe offline decoding
- `sha256sum` for image integrity

---

## Investigation

### Process Discovery
- `pslist` showed no active PowerShell process.  
- `psscan` recovered PID 4296 (`powershell.exe`) that had already exited.  
- `pstree` confirmed the lineage: parent PID 4308, child `conhost.exe`.  

**MITRE Mapping:**  
- **T1057 – Process Discovery** (attacker visibility of running processes)  
- **T1059.001 – Command and Scripting Interpreter: PowerShell**  

**Screenshots:**  
- `02-psscan_pid4296.png`  
- `03-pstree_pid4296.png`

---

### Command-Line Arguments
- `cmdline` returned only the executable path (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).  
- No `-EncodedCommand` flag recovered — a common limitation once processes exit.  

**MITRE Mapping:**  
- **T1059.001 – PowerShell** (PowerShell execution observed)  

**Screenshot:**  
- `04-cmdline-hits.png`

---

### EncodedCommand Discovery
- UTF-16LE string sweep across the image revealed repeated PowerShell executions with `-EncodedCommand` and a long base64 blob.  

**MITRE Mapping:**  
- **T1027 – Obfuscated/Encrypted File or Information** (use of Base64 to hide payloads)  
- **T1059.001 – PowerShell** (use of encoded PowerShell commands)  

**Screenshot:**  
- `05-strings-encodedcommand.png`

---

### Decoded Payload
- Extracted the base64 blob and decoded safely offline (UTF-16LE → UTF-8).  
- Payload was a benign test script that wrote a marker file (`ps_test.txt`) and then slept for 600 seconds.  

**MITRE Mapping:**  
- **T1059 – Command and Scripting Interpreter**  
- **T1070.004 – Indicator Removal on Host: File Deletion** (if attackers later remove files created)  
- **T1497.001 – Virtualization/Sandbox Evasion: System Checks** (use of `Start-Sleep` to evade sandbox timeouts)  

**Screenshot:**  
- `06-decoded_payload_snippet.png`

---

## Results
- `psscan` recovered the hidden PowerShell process (PID 4296).  
- `pstree` confirmed parent/child relationships.  
- Strings analysis uncovered the encoded PowerShell payload.  
- Decoded script confirmed expected behavior (file write + sleep).  
- SHA256 hash recorded for image integrity.  

**MITRE Summary:**  
- **T1059.001 – PowerShell**  
- **T1027 – Obfuscated/Encoded Commands**  
- **T1497.001 – Sandbox Evasion (sleep)**  
- **T1057 – Process Discovery**  

---

## Lessons Learned
- `pslist` alone is not reliable — `psscan` is needed for terminated processes.  
- Encoded PowerShell payloads remain recoverable in memory as UTF-16LE.  
- Even negative findings (like empty `cmdline`) provide valuable context.  
- Practiced SOC-relevant skills: process hunting, payload recovery, safe offline decoding, and structured DFIR reporting.  

---

## Next Steps
- Extend analysis to persistence detection (registry hives, scheduled tasks).  
- Correlate findings with enterprise threat hunting (MITRE ATT&CK mapping).  
- Apply Yara rules to memory dumps for known malware families.  
- Compare dumps pre- and post-infection to demonstrate attack progression.  

---

## Author
**Ayrton Cook**  
BSc Computer Science with Year in Industry
University of East Anglia
