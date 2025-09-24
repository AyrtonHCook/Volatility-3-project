# Windows Memory Forensics with Volatility 3

## Project Overview
This project looks at analysing a Windows 10 memory dump using **Volatility 3** on a REMnux VM.  
The goal was to simulate an incident where malware is suspected and then investigate the dump to confirm what happened.  

I captured the RAM dump from a Windows 10 VM using **FTK Imager**, then ran Volatility 3 to dig into processes, network activity, and command lines.  

---

## Setup

1. **Windows 10 Victim VM**
   - Simulated malware execution (PowerShell with an encoded command).
   - Took a memory snapshot using FTK Imager.

2. **Analysis Environment**
   - Used **REMnux** (DFIR-focused Linux distro).
   - Installed Volatility 3 (preloaded on REMnux).
   - Verified it worked:  
     ```bash
     python3 vol.py -h
     ```

---

## Analysis

### Process Listing
Command:
```bash
python3 vol.py -f memdump.raw windows.pslist
```
Screenshot: show the running processes, highlight the suspicious `powershell.exe`.

---

### Process Tree
Command:
```bash
python3 vol.py -f memdump.raw windows.pstree
```
Screenshot: capture the parent/child relationship where PowerShell was spawned.

---

### Command Line Arguments
Command:
```bash
python3 vol.py -f memdump.raw windows.cmdline
```
Screenshot: show the `-EncodedCommand` argument (this confirms malicious activity).  
Redact any sensitive file paths if needed.

---

### Network Connections
Command:
```bash
python3 vol.py -f memdump.raw windows.netscan
```
Screenshot: capture any outbound connection linked to PowerShell or suspicious processes.

---

## Findings

- Discovered a **PowerShell process** with an `-EncodedCommand` argument.
- This indicates possible script-based malware execution.
- The process tree shows PowerShell was spawned abnormally, suggesting attacker activity.
- Network connections showed [fill in what you found].

---

## Lessons Learned

- Learned how to acquire a memory dump safely with FTK Imager.
- Practiced running Volatility 3 commands and interpreting the output.
- Saw how PowerShell misuse can be spotted in memory (not just logs).
- Realised the importance of correlating process, command line, and network data.

---

## Next Steps

- Try extracting the encoded PowerShell command from memory.
- Add YARA scanning with Volatility to hunt for known malware strings.
- Compare memory analysis with log-based detection (link this project to Sentinel lab).

