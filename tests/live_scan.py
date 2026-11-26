"""Exercise the live scanner on a disposable Windows machine with active Defender."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import os
import subprocess
import tempfile
import time


def run_folder_scan(dll, case, folder):
    scan = subprocess.run(["dotnet", dll, "scan", case, "folder", folder], check=False)
    if not case.is_file():
        raise RuntimeError("The scanner did not create a case. Check Windows and Defender availability.")
    report = subprocess.check_output(["dotnet", dll, "show", case, "--paths"], encoding="utf-8")
    return scan.returncode, json.loads(report)


def checked_request(report, folder):
    request, = report["scanRequests"]
    if request["kind"] != "folder" or Path(request["folder"]) != folder:
        raise ValueError("The saved request does not match the test folder.")
    if not request["engineVersion"] or not request["signatureVersion"]:
        raise ValueError(f"Defender did not provide its versions. Request error: {request['error']}")
    return request


def resources(detection):
    for field in detection.get("resources") or []:
        for entry in field.split(";"):
            path = entry.strip().split(":_", 1)[-1]
            yield os.path.normcase(os.path.normpath(path))


def completed_custom_scan(report, request):
    for scan in report["scans"]:
        if (scan["mode"] == "live" and scan["kind"] == "custom" and scan["status"] == "completed"
                and scan["device"].casefold() == request["device"].casefold()
                and scan["startedUtc"] and scan["startedUtc"] >= request["requestedUtc"]):
            return True
    return False


def test_benign(dll, root):
    folder = root / "100 benign documents"
    folder.mkdir()
    manifest = {}
    for index in range(100):
        path = folder / f"document-{index:03}.txt"
        data = f"HexSuture benign test document {index}\n".encode("ascii")
        path.write_bytes(data)
        manifest[path.name] = hashlib.sha256(data).hexdigest()
    (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    code, report = run_folder_scan(dll, root / "benign.db", folder)
    request = checked_request(report, folder)
    if code or report["sourceGaps"] or not completed_custom_scan(report, request):
        raise ValueError(f"Benign scan incomplete. Exit {code}, coverage gaps: {report['sourceGaps']}")
    corpus = {os.path.normcase(str(folder / name)) for name in manifest}
    flagged = {path for item in report["detections"] for path in resources(item)} & corpus
    print(f"Benign scan: {len(flagged)}/100 files flagged; engine {request['engineVersion']}, signatures {request['signatureVersion']}.", flush=True)
    if flagged:
        raise ValueError("Defender flagged a benign fixture.")
    for name, expected in manifest.items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Benign file changed: {name}")


def test_eicar(dll, root):
    folder = root / "EICAR check"
    folder.mkdir()
    sample = folder / "eicar-test.txt"
    # EICAR's harmless 68-byte signature is written only in the disposable test folder.
    data = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    try:
        sample.write_bytes(data)
    except OSError as error:
        if getattr(error, "winerror", None) not in (5, 225, 226):
            raise
    # Give on-access protection time to record a detection before requesting the scan.
    time.sleep(5)
    code, report = run_folder_scan(dll, root / "eicar.db", folder)
    request = checked_request(report, folder)
    matches = [item for item in report["detections"] if item["mode"] == "live"
               and "eicar" in (item["threatName"] or "").lower()
               and os.path.normcase(str(sample)) in set(resources(item)) and item["detectedUtc"]]
    if not matches:
        raise ValueError(f"No live EICAR detection identified this sample. Scanner exit {code}; coverage gaps: {report['sourceGaps']}")
    first = min(matches, key=lambda item: item["detectedUtc"])
    before = datetime.fromisoformat(first["detectedUtc"].replace("Z", "+00:00")) < datetime.fromisoformat(request["requestedUtc"].replace("Z", "+00:00"))
    print(f"EICAR: source={first['source']}; before scan request={before}; action={first['action']}; action status={first['actionStatus']}.", flush=True)
    if first["source"] == "unknown" or report["sourceGaps"] or not completed_custom_scan(report, request):
        raise ValueError("EICAR was observed but scan evidence or detection attribution was incomplete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    parser.add_argument("--eicar", action="store_true", help="Also create the harmless EICAR test file.")
    args = parser.parse_args()
    if os.name != "nt" or not args.dll.is_file():
        parser.error("Run on Windows with a built HexSuture DLL.")
    with tempfile.TemporaryDirectory(prefix="hexsuture-scan-") as tmp:
        base = Path(tmp).resolve()
        dll_path = args.dll.resolve()
        test_benign(dll_path, base)
        if args.eicar:
            test_eicar(dll_path, base)
