# APK Scam Scanner

This is an offline-first defensive scanner for APK files received from unknown people. It never installs, launches, emulates, or executes an APK. It reads the file as a ZIP archive and inspects metadata and readable content only.

## Requirements

- Windows, macOS, or Linux
- Python 3.11 or newer
- Optional: Android SDK Build Tools for richer manifest decoding (`aapt`)
- Optional: a VirusTotal API key stored in the `VT_API_KEY` environment variable

## Safe usage

From this folder:

```powershell
python .\apk_scam_scanner.py "C:\path\to\suspicious.apk"
```

Every scan automatically creates a `reports` folder beside the `.py` file (or beside the `.exe` when packaged). It writes one timestamped, self-contained `.html` report and opens it in the browser. Existing reports are never overwritten. The report starts with a plain-language verdict and contains all technical details in an expandable section.

To open a file picker:

```powershell
python .\apk_scam_scanner.py
```

The report includes the SHA-256 hash, package identity, label, SDK versions, permissions, launcher, native ABIs, archive anomalies, encrypted members, readable URLs/strings, capability indicators, and a cautious intent assessment. Use `--no-open-report` when running from a terminal or automated process.

`--open-vt` opens VirusTotal's public hash page after calculating the hash. It does not upload the APK and does not require an API key. The generated report also includes this link:

```powershell
python .\apk_scam_scanner.py "C:\path\to\suspicious.apk" --open-vt
```

## VirusTotal

Hash lookup does not upload the file:

```powershell
$env:VT_API_KEY = "paste-your-key-here"
python .\apk_scam_scanner.py "C:\path\to\suspicious.apk" --vt
```

If the hash is unknown to VirusTotal, upload only with explicit opt-in:

```powershell
python .\apk_scam_scanner.py "C:\path\to\suspicious.apk" --vt --upload-to-vt
```

VirusTotal submissions may be shared with security vendors and researchers. Do not upload private, proprietary, regulated, or personally sensitive APKs without permission. The API key is read from the environment and is never written into the report.

Do not scrape VirusTotal's website. The public page can be opened for a human to review, but automated scraping is fragile and may conflict with service terms. A shared application should use an organization-owned backend or ask each user for their own API key if automated VirusTotal lookups are required. Never put your personal API key in the executable.

## Build a Windows executable

Install PyInstaller on the build machine, then build a windowless executable:

```powershell
python -m pip install --upgrade pyinstaller
pyinstaller --clean --noconfirm .\APK-Scam-Scanner.spec
```

The executable will be in `dist`. A senior or nontechnical user can double-click it, choose an APK, and read the report that opens automatically. Copy it to a folder where it can create a sibling `reports` folder. The app can use Android SDK `aapt` when it is installed on the user's machine; without it, the scanner still performs ZIP, hash, archive, and readable-content analysis. Do not bundle or invoke `adb`, an emulator, `java`, `apktool`, or any installer in this tool.

## Important limits

Static analysis cannot prove that an APK is genuine, and it cannot always reveal behavior hidden in encrypted, packed, native, or dynamically downloaded code. A verdict of `No conclusion` does not mean safe. Any APK received through an unsolicited message should remain uninstalled unless its source and signature are independently verified.

For a suspicious result, preserve the original file and hash, do not open it on a phone, and submit the report and hash to your security team or a reputable malware-analysis service. If it was installed already, disconnect the device from networks and contact the bank or service provider using a trusted device.
