# 🔍 LOLBinFinder

A PowerShell script that scans for known **LOLBins** or **vulnerable DLLs/executables** on the local system by resolving environment variables and wildcard versions in file paths. Useful for security research, red teaming, or detection engineering.

## 📦 Features

- Expands environment variables (e.g., `%PROGRAMFILES%`, `%APPDATA%`, `%USERPROFILE%`, etc.)
- Supports `<version>` wildcards in paths
- Outputs results to the console, `.csv`, or `.txt`
- Detects presence, size, and metadata of known vulnerable binaries
- Useful for detecting misused Microsoft-signed binaries (LOLBins)

## 🛠 Usage

- Use the relevant Python script to pull a list of the latest vulnerable dll/binary file paths
```bash
python3 HijackLibsOutput.py

python3 LOLBasOutput.py
```

```powershell
.\Find-VulnerableFiles.ps1 -ListFile "vulnerable_dlls.txt"

.\Find-VulnerableFiles.ps1 -ListFile "lolbas_paths.txt"
```

## Optional Parameters:

- ListFile	(Required) Path to file containing the list of file paths
- OutputFile	Path to save results as a CSV
- TextOutputFile	Path to save results as a TXT
- FoundOnly	Show only files that are found
- Help	Display help message


⚠️ Disclaimer
This script is intended for educational and research purposes only. Do not use it on systems you do not own or have explicit permission to analyze.

🔗 References

- [LOLBAS Project](https://lolbas-project.github.io/)
- [hijacklibs Project](https://hijacklibs.net/)

