# 🕵️‍♂️ ProcessMasquerading

A minimal C project demonstrating **runtime modification** of a process's identity by manipulating the **PEB (Process Environment Block)**. The tool spoofs the current process’s:

- **Command line**
- **Image path**
- **Current directory**

Useful for:
- Malware analysis & red teaming
- Evasion technique research
- Low-level Windows internals exploration

---

## ⚙️ Features

- Rewrites `CommandLine` and `ImagePathName` in memory via direct access to the PEB
- Changes current directory via both `SetCurrentDirectoryW` and PEB `CurrentDirectory`
- Embeds a custom icon (e.g., `notepad.ico`) to complete the disguise
- Pure WinAPI (no external dependencies)

---

## 🛠️ Build

### 📁 Requirements
- Windows 10/11 (x64)
- Visual Studio (or MSVC CLI)
- Valid `.ico` file (256x256 recommended)

### 🧱 Compile via CLI

```powershell
rc resource.rc
cl main.c resource.res /Fe:x64\Release\ProcessMasquerading.exe /link /SUBSYSTEM:CONSOLE
```

## ⚠️ Disclaimer

This project is for educational and research purposes only.
Use responsibly and never in unauthorized environments.
