# Windows Memory Forensics: Volatility 3 Analysis

## Project Overview
For this project I used [Volatility 3](https://github.com/volatilityfoundation/volatility3) on REMnux to investigate a Windows 10 memory dump.  
The aim was to simulate a DFIR workflow: identify suspicious processes, recover command-line arguments, extract encoded payloads, and decode them safely.  
This helped me practice memory forensics, artifact hunting, and documenting findings.

---

## Setup
**Environment**
- Host: REMnux VM with Volatility 3 Framework 2.7.0
- Image: Windows 10 memory dump (`memdump.dmp`)
- Target: `powershell.exe` (PID 4296)

**Tools**
- Volatility 3 (core plugins: `psscan`, `pstree`, `cmdline`, `strings`)
- `strings` for UTF-16LE scanning
- `base64` + `iconv` for safe offline decoding
- `sha256sum` for image integrity

---

## Investigation

### Process Discovery
- `pslist` showed no PowerShell process.  
- `psscan` revealed PID 4296 (`powershell.exe`) that had already exited.  
- `pstree` showed the lineage: parent PID 4308, child `conhost.exe`.

**Screenshots:**  
- `psscan_pid4296.png`  
- `pstree_pid4296.png`

---

### Command-Line Arguments
- `cmdline` returned only the executable path (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).  
- No `-EncodedCommand` present, a common limitation when processes exit.

**Screenshot:**  
- `04-cmdline-hits.png`

---

### EncodedCommand Discovery
- Ran a UTF-16LE string sweep across the image.  
- Found repeated instances of PowerShell launched with `-EncodedCommand` and a long base64 blob.

**Screenshot:**  
- `05-strings-encodedcommand.png`

---

### Decoded Payload
- Extracted the base64 blob.  
- Decoded safely (UTF-16LE → UTF-8).  
- Payload was a benign test script:

```powershell
Write-Output "DFIR TEST RUN" | Out-File C:\Temp\ps_test.txt -Encoding UTF8
Start-Sleep -Seconds 600
```

**Screenshot:**  
- `06-decoded_payload_snippet.png`

---

## Results
- `psscan` recovered the hidden PowerShell process (PID 4296).  
- `pstree` confirmed parent/child relationships.  
- Strings analysis uncovered the encoded payload arguments.  
- Decoded script matched expected test behavior (output file + sleep).  
- SHA256 hash recorded for image integrity.

---

## Lessons Learned
- `pslist` alone is not reliable — `psscan` is needed for terminated processes.  
- Encoded PowerShell payloads remain recoverable in memory as UTF-16LE.  
- Even negative findings (like empty `cmdline`) give useful context.  
- Safe offline decoding avoids execution risks.  

---

## Next Steps
- Test Volatility plugins like `envars`, `handles`, `vadinfo`, and `malfind` on more realistic samples.  
- Combine with registry hive analysis (`printkey`) for persistence detection.  
- Document comparisons across multiple dumps (before/after infection).  
- Extend project with a Yara scan for known indicators.

---

## Author
**Ayrton Cook**  
BSc Computer Science with Year in Industry (Cybersecurity focus)  
University of East Anglia
