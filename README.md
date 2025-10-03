# Windows Memory Forensics: Volatility 3

**Goal:** Demonstrate memory forensic analysis of a Windows 10 dump using Volatility 3.  
**Skills Gained:** Process discovery, command-line artefact recovery, decoding payloads, MITRE mapping.

---

## Overview
This project simulates an incident response workflow on a Windows 10 memory image.  
Using Volatility 3 on REMnux, I identified suspicious processes, extracted PowerShell `-EncodedCommand` payloads, and decoded them safely.

---

## Quick Start
```bash
python3 vol.py -f memdump.dmp windows.psscan
python3 vol.py -f memdump.dmp windows.cmdline
strings -el memdump.dmp | grep EncodedCommand
```

---

## Results
- Identified malicious PowerShell payloads executed via `-EncodedCommand`.  
- Decoded payload revealed script execution attempts.  

---

## MITRE ATT&CK Mapping
| Tactic         | Technique                        | Evidence                  |
|----------------|----------------------------------|---------------------------|
| Execution      | T1059.001 (PowerShell)           | EncodedCommand in memory  |
| Defense Evasion| T1027 (Obfuscated Scripts)       | Base64-encoded payload    |

---

## Documentation
- Full case study: [`/docs/volatility-case-study.md`](docs/volatility-case-study.md)  
- Screenshots in `/screenshots/`  
- Artefacts in `/artifacts/`

---

## Roadmap
- Extend to timeline analysis  
- Add YARA scanning  
- Compare with Rekall framework
