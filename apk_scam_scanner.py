from __future__ import annotations

import argparse
import html
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
import webbrowser
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_TEXT_BYTES = 8 * 1024 * 1024
STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")
MAX_REPORTED_STRINGS = 500
MAX_STRING_LENGTH = 240

CAPABILITY_PATTERNS = {
    "APK installation / dropper": ("request_install_packages", "dynamicinstall", "packageinstaller", "installpackages"),
    "Broad installed-app discovery": ("query_all_packages", "getinstalledpackages", "getinstalledapplications"),
    "SMS or OTP access": ("read_sms", "receivesms", "sms", "otp", "verification code"),
    "Accessibility abuse": ("accessibilityservice", "accessibility", "performglobalaction"),
    "Overlay / screen deception": ("system_alert_window", "drawoverlays", "overlay", "fake google play", "system update"),
    "Credential or payment-data targeting": ("password", "passcode", "credit card", "card number", "cvv", "bank", "login"),
    "Command or shell execution": ("runtime.getruntime", "processbuilder", "/system/bin/sh", "exec("),
    "Remote communication": ("http://", "https://", "webview", "socket", "firebase", "telegram"),
}


def application_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def next_report_path() -> Path:
    reports_directory = application_directory() / "reports"
    reports_directory.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = reports_directory / f"apk-report-{timestamp}"
    report_path = base.with_suffix(".html")
    counter = 1
    while report_path.exists():
        report_path = reports_directory / f"apk-report-{timestamp}-{counter}.html"
        counter += 1
    return report_path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strings_from_bytes(data: bytes) -> list[str]:
    strings = []
    for match in STRING_RE.finditer(data):
        value = match.group().decode("ascii", "ignore").strip()
        if value:
            strings.append(value[:MAX_STRING_LENGTH])
    return strings


def find_aapt() -> str | None:
    candidates = [shutil.which("aapt"), shutil.which("aapt2")]
    sdk = Path(os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", "")))
    if sdk:
        candidates.extend(str(path) for path in sdk.glob("build-tools/*/aapt.exe"))
    local_sdk = Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk"
    candidates.extend(str(path) for path in local_sdk.glob("build-tools/*/aapt.exe"))
    for candidate in reversed([item for item in candidates if item]):
        if Path(candidate).exists() or shutil.which(candidate):
            return candidate
    return None


def read_aapt_badging(path: Path) -> tuple[str, str | None]:
    aapt = find_aapt()
    if not aapt:
        return "aapt/aapt2 not found; manifest details are limited.", None
    try:
        startupinfo = None
        creationflags = 0
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0
            creationflags = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(
            [aapt, "dump", "badging", str(path)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        return output, aapt
    except (OSError, subprocess.SubprocessError) as error:
        return f"Manifest reader unavailable: {error}", aapt


def inspect_archive(path: Path) -> dict[str, Any]:
    findings: list[str] = []
    readable_text: list[str] = []
    entries: list[dict[str, Any]] = []
    encrypted: list[str] = []
    suspicious_names: list[str] = []
    with zipfile.ZipFile(path) as archive:
        bad_member = None
        for info in archive.infolist():
            is_encrypted = bool(info.flag_bits & 0x1)
            record = {
                "name": info.filename,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "encrypted": is_encrypted,
                "comment": info.comment.decode("utf-8", "replace") if info.comment else "",
            }
            entries.append(record)
            if is_encrypted:
                encrypted.append(info.filename)
            if "APKEditor" in record["comment"] or "Zip Confuser" in record["comment"]:
                findings.append(f"Archive member is marked: {record['comment']}")
            if re.search(r"(?:AndroidManifest\.xml|classes\.dex|resources\.arsc|res/values|kotlin/).*(?:\.png|\.xml|\\)", info.filename, re.IGNORECASE):
                suspicious_names.append(info.filename)
            if not is_encrypted and info.file_size <= MAX_TEXT_BYTES:
                try:
                    data = archive.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    bad_member = bad_member or info.filename
                    continue
                if info.filename.lower().endswith((".dex", ".so", ".xml", ".html", ".cache", ".properties", ".textproto")):
                    readable_text.extend(strings_from_bytes(data))
                    if info.filename.lower().endswith((".html", ".xml", ".properties", ".textproto")):
                        readable_text.append(data.decode("utf-8", "replace"))
    if bad_member:
        findings.append(f"ZIP integrity check failed at member: {bad_member}")
    if encrypted:
        findings.append(f"{len(encrypted)} payload member(s) are encrypted and were not read")
    if suspicious_names:
        findings.append(f"{len(suspicious_names)} path-confusable or disguised member name(s) detected")
    unique_strings = sorted(set(readable_text))
    urls = sorted({url for value in unique_strings for url in re.findall(r"https?://[^\x00\s\"'<>]+", value, re.IGNORECASE)})
    domains = sorted({domain.lower() for value in unique_strings for domain in re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|app|site|online|xyz|top|ru|cn)\b", value, re.IGNORECASE)})
    return {
        "entry_count": len(entries),
        "entries": entries,
        "encrypted_members": encrypted,
        "suspicious_names": suspicious_names[:100],
        "findings": sorted(set(findings)),
        "strings": unique_strings[:MAX_REPORTED_STRINGS],
        "readable_string_count": len(unique_strings),
        "urls": urls[:100],
        "domains": domains[:100],
    }


def parse_badging(badging: str) -> dict[str, Any]:
    result: dict[str, Any] = {"package": None, "version": None, "label": None, "launcher": None, "permissions": [], "native_abis": []}
    match = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", badging)
    if match:
        result["package"], result["version_code"], result["version"] = match.groups()
    label = re.search(r"application-label:'([^']*)'", badging)
    if label:
        result["label"] = label.group(1)
    launcher = re.search(r"launchable-activity: name='([^']+)'", badging)
    if launcher:
        result["launcher"] = launcher.group(1)
    result["permissions"] = sorted(set(re.findall(r"uses-permission: name='([^']+)'", badging)))
    result["native_abis"] = sorted(set(re.findall(r"native-code: '([^']+)'", badging)))
    result["target_sdk"] = (re.search(r"targetSdkVersion:'([^']+)'", badging) or [None, None])[1]
    result["compile_sdk"] = (re.search(r"compileSdkVersion='([^']+)'", badging) or [None, None])[1]
    return result


def infer_intent(metadata: dict[str, Any], archive: dict[str, Any]) -> dict[str, Any]:
    haystack = "\n".join(archive["strings"]).lower()
    haystack += "\n" + "\n".join(metadata.get("permissions", [])).lower()
    capabilities: dict[str, list[str]] = {}
    for name, terms in CAPABILITY_PATTERNS.items():
        hits = sorted({term for term in terms if term in haystack})
        if hits:
            capabilities[name] = hits
    score = 0
    reasons: list[str] = []
    permissions = set(metadata.get("permissions", []))
    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions:
        score += 4
        reasons.append("can request permission to install additional APKs")
    if "android.permission.QUERY_ALL_PACKAGES" in permissions:
        score += 2
        reasons.append("can enumerate installed applications")
    if metadata.get("launcher") and "install" in metadata["launcher"].lower():
        score += 3
        reasons.append("launcher name suggests an installation/dropper workflow")
    if metadata.get("label") and re.search(r"credit|loan|bank|update|play", metadata["label"], re.IGNORECASE):
        score += 2
        reasons.append("financial or system-update branding is present")
    if archive["encrypted_members"]:
        score += 3
        reasons.append("main code or native payload is encrypted in the APK archive")
    if capabilities.get("Credential or payment-data targeting") or capabilities.get("SMS or OTP access"):
        score += 3
        reasons.append("readable code/resources contain credential, payment, SMS, or OTP terms")
    if score >= 9:
        verdict = "Highly suspicious / likely malicious"
    elif score >= 5:
        verdict = "Suspicious; manual malware analysis recommended"
    else:
        verdict = "No conclusion from static indicators"
    intent = "Unknown; protected code prevents exact attribution."
    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions or "APK installation / dropper" in capabilities:
        intent = "Likely a deceptive installer/dropper intended to persuade the victim to install a second-stage APK or payload."
    return {"verdict": verdict, "score": score, "likely_intent": intent, "reasons": reasons, "capabilities": capabilities}


def vt_request(url: str, api_key: str, method: str = "GET", data: bytes | None = None, content_type: str | None = None) -> tuple[int, Any]:
    request = urllib.request.Request(url, data=data, method=method, headers={"x-apikey": api_key, "Accept": "application/json"})
    if content_type:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        try:
            return error.code, json.loads(body)
        except json.JSONDecodeError:
            return error.code, {"error": body}
    except (OSError, TimeoutError) as error:
        return 0, {"error": str(error)}


def virus_total(path: Path, digest: str, upload: bool) -> dict[str, Any]:
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return {"status": "skipped", "reason": "VT_API_KEY is not set"}
    status, report = vt_request(f"https://www.virustotal.com/api/v3/files/{digest}", api_key)
    result: dict[str, Any] = {"lookup_status": status, "lookup": report}
    if status == 200 or not upload:
        return result
    if status != 404:
        return result
    boundary = uuid.uuid4().hex
    filename = path.name.encode("utf-8")
    file_bytes = path.read_bytes()
    body = b"--" + boundary.encode() + b"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename + b"\"\r\nContent-Type: application/vnd.android.package-archive\r\n\r\n" + file_bytes + b"\r\n--" + boundary.encode() + b"--\r\n"
    upload_status, upload_result = vt_request("https://www.virustotal.com/api/v3/files", api_key, "POST", body, f"multipart/form-data; boundary={boundary}")
    result["upload_status"] = upload_status
    result["upload"] = upload_result
    return result


def open_virus_total_page(digest: str) -> bool:
    return webbrowser.open(f"https://www.virustotal.com/gui/file/{digest}/detection")


def format_report(report: dict[str, Any]) -> str:
    meta = report["metadata"]
    intent = report["assessment"]
    lines = ["APK STATIC SAFETY REPORT", "=" * 25, f"File: {report['file']}", f"SHA-256: {report['sha256']}", "", f"Verdict: {intent['verdict']}", f"Likely intent: {intent['likely_intent']}", "", "Identity:"]
    for key in ("package", "label", "version", "target_sdk", "launcher"):
        lines.append(f"  {key}: {meta.get(key) or 'unknown'}")
    lines.append("Permissions:")
    lines.extend(f"  - {item}" for item in meta.get("permissions", []))
    lines.append("Reasons:")
    lines.extend(f"  - {item}" for item in intent["reasons"] or ["No high-confidence indicator found."])
    lines.append("Capabilities observed in readable content:")
    lines.extend(f"  - {name}: {', '.join(hits)}" for name, hits in intent["capabilities"].items())
    lines.append("Archive protection/findings:")
    lines.extend(f"  - {item}" for item in report["archive"]["findings"] or ["None"])
    if report.get("virustotal", {}).get("status") not in ("skipped", "not requested"):
        lines.append("VirusTotal: see JSON report for the complete API response.")
    if report.get("virustotal_web"):
        lines.append("VirusTotal web page: opened without uploading the file.")
    return "\n".join(lines)


def format_html_report(report: dict[str, Any]) -> str:
    text_report = html.escape(format_report(report))
    details = html.escape(json.dumps(report, indent=2, ensure_ascii=True))
    digest = report["sha256"]
    vt_url = f"https://www.virustotal.com/gui/file/{digest}/detection"
    verdict = html.escape(report["assessment"]["verdict"])
    likely_intent = html.escape(report["assessment"]["likely_intent"])
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APK Safety Report</title>
<style>
body {{ margin: 0; background: #f4f6f8; color: #17202a; font: 16px/1.5 Segoe UI, sans-serif; }}
main {{ max-width: 900px; margin: 32px auto; padding: 0 20px; }}
section {{ background: white; border: 1px solid #d8dee4; border-radius: 8px; padding: 22px; margin: 16px 0; }}
h1 {{ margin-top: 0; }}
.verdict {{ border-left: 6px solid #b42318; padding-left: 16px; }}
.verdict strong {{ font-size: 22px; }}
a {{ color: #075985; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #111827; color: #e5e7eb; padding: 16px; border-radius: 6px; font-size: 12px; }}
.note {{ color: #4b5563; }}
</style>
</head>
<body><main>
<section><h1>APK Safety Report</h1>
<div class="verdict"><strong>{verdict}</strong><p>{likely_intent}</p></div>
<p><strong>File:</strong> {html.escape(report["file"])}</p>
<p><strong>SHA-256:</strong> {digest}</p>
<p><a href="{vt_url}">View this file hash on VirusTotal</a> (opens the public page; the APK was not uploaded by this report).</p>
</section>
<section><h2>What was found</h2><pre>{text_report}</pre></section>
<section><details><summary>Technical details</summary><pre>{details}</pre></details></section>
<p class="note">This is static analysis. A clean or inconclusive result is not proof that an APK is safe. Never install an APK received unexpectedly.</p>
</main></body></html>"""


def choose_path() -> Path:
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        selected = filedialog.askopenfilename(title="Select suspicious APK", filetypes=[("Android packages", "*.apk"), ("All files", "*.*")])
        root.destroy()
        if selected:
            return Path(selected)
    except Exception:
        pass
    raise SystemExit("No APK path supplied and the file picker is unavailable.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline-first static scanner for suspicious Android APKs. Never installs or runs APKs.")
    parser.add_argument("path", nargs="?", help="path to an APK; omit to open a file picker")
    parser.add_argument("--vt", action="store_true", help="query VirusTotal by SHA-256; requires VT_API_KEY")
    parser.add_argument("--upload-to-vt", action="store_true", help="upload only after explicit opt-in; requires --vt and VT_API_KEY")
    parser.add_argument("--open-vt", action="store_true", help="open the public VirusTotal hash page; does not upload the file")
    parser.add_argument("--no-open-report", action="store_true", help="do not open the generated report in the browser")
    args = parser.parse_args()
    if args.upload_to_vt and not args.vt:
        parser.error("--upload-to-vt requires --vt")
    try:
        path = Path(args.path) if args.path else choose_path()
        if not path.is_file() or path.suffix.lower() != ".apk":
            parser.error("path must be an existing .apk file")
        try:
            with zipfile.ZipFile(path) as archive:
                archive.getinfo("AndroidManifest.xml")
        except (OSError, zipfile.BadZipFile, KeyError) as error:
            parser.error(f"not a readable APK/ZIP archive: {error}")
        digest = sha256_file(path)
        badging, analyzer = read_aapt_badging(path)
        metadata = parse_badging(badging)
        archive = inspect_archive(path)
        assessment = infer_intent(metadata, archive)
        report = {"file": str(path.resolve()), "sha256": digest, "metadata": metadata, "manifest_reader": analyzer, "archive": archive, "assessment": assessment}
        if args.vt:
            report["virustotal"] = virus_total(path, digest, args.upload_to_vt)
        else:
            report["virustotal"] = {"status": "not requested"}
        if args.open_vt:
            report["virustotal_web"] = {"url": f"https://www.virustotal.com/gui/file/{digest}/detection", "opened": open_virus_total_page(digest)}
        report_path = next_report_path()
        report_path.write_text(format_html_report(report), encoding="utf-8")
        print(format_report(report))
        print(f"\nReport written to:\n  {report_path}")
        if not args.no_open_report:
            webbrowser.open(report_path.as_uri())
    except SystemExit:
        raise
    except Exception as error:
        try:
            import tkinter.messagebox as messagebox
            messagebox.showerror("APK Scam Scanner", f"The scan could not be completed:\n\n{error}")
        except Exception:
            print(f"The scan could not be completed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
