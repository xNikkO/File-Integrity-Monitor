import os
import sys
import json
import time
import hashlib
import argparse
import urllib.error
import urllib.request
from datetime import datetime


CHUNK_SIZE = 64 * 1024

VT_API_URL = "https://www.virustotal.com/api/v3/files/"
VT_GUI_URL = "https://www.virustotal.com/gui/file/"
VT_REQUEST_INTERVAL_SEC = 15  # darmowy plan: 4 zapytania / min
VT_REQUEST_TIMEOUT_SEC = 20

EXECUTABLE_EXTENSIONS = {
    # Windows
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".msi", ".msp", ".jar",
    # Linux / Unix
    ".sh", ".bin", ".elf", ".out", ".run", ".so",
    # macOS
    ".app", ".dmg", ".pkg", ".dylib",
    # Mobilne
    ".apk", ".ipa",
}

EXECUTABLE_MAGIC_BYTES = (
    b"MZ",                  # PE (Windows .exe, .dll, .sys)
    b"\x7fELF",             # ELF (Linux)
    b"\xCA\xFE\xBA\xBE",    # Mach-O fat binary / Java class
    b"\xFE\xED\xFA\xCE",    # Mach-O 32-bit
    b"\xFE\xED\xFA\xCF",    # Mach-O 64-bit
    b"\xCE\xFA\xED\xFE",    # Mach-O 32-bit (LE)
    b"\xCF\xFA\xED\xFE",    # Mach-O 64-bit (LE)
    b"#!",                  # Skrypty z shebangiem (#!/bin/bash, #!/usr/bin/env python ...)
)


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except PermissionError:
        print(f"[OSTRZEZENIE] Brak uprawnien do pliku: {file_path}")
        return None
    except (OSError, IOError) as e:
        print(f"[OSTRZEZENIE] Nie mozna odczytac pliku {file_path}: {e}")
        return None


def scan_directory(root_dir):
    file_hashes = {}

    if not os.path.isdir(root_dir):
        print(f"[BLAD] Podana sciezka nie jest katalogiem: {root_dir}")
        sys.exit(1)

    def _walk_error(err):
        print(f"[OSTRZEZENIE] Problem z dostepem podczas skanowania: {err}")

    for current_dir, _subdirs, files in os.walk(root_dir, onerror=_walk_error):
        for filename in files:
            full_path = os.path.join(current_dir, filename)
            rel_path = os.path.relpath(full_path, root_dir).replace(os.sep, "/")

            file_hash = calculate_sha256(full_path)
            if file_hash is not None:
                file_hashes[rel_path] = file_hash

    return file_hashes


def is_executable_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in EXECUTABLE_EXTENSIONS:
        return True

    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
    except (OSError, IOError):
        return False

    return any(header.startswith(magic) for magic in EXECUTABLE_MAGIC_BYTES)


def query_virustotal(file_hash, api_key):
    request = urllib.request.Request(
        VT_API_URL + file_hash,
        headers={
            "x-apikey": api_key,
            "accept": "application/json",
            "User-Agent": "FIM-Python/1.0",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=VT_REQUEST_TIMEOUT_SEC) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found"}
        if e.code == 401:
            return {"status": "error", "message": "Nieprawidlowy klucz API (401)"}
        if e.code == 429:
            return {"status": "error", "message": "Przekroczono limit zapytan API (429)"}
        return {"status": "error", "message": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        return {"status": "error", "message": f"Blad polaczenia: {e.reason}"}
    except (json.JSONDecodeError, ValueError) as e:
        return {"status": "error", "message": f"Niepoprawna odpowiedz API: {e}"}

    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}

    return {
        "status": "found",
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "timeout": int(stats.get("timeout", 0) or 0),
        "meaningful_name": attributes.get("meaningful_name"),
        "type_description": attributes.get("type_description"),
    }


def collect_executables(target_dir, file_hashes, only_paths=None):
    selected = []
    for rel_path, file_hash in file_hashes.items():
        if only_paths is not None and rel_path not in only_paths:
            continue
        full_path = os.path.join(target_dir, rel_path.replace("/", os.sep))
        if is_executable_file(full_path):
            selected.append((rel_path, file_hash))
    return selected


def virustotal_scan(target_dir, file_hashes, api_key, only_paths=None):
    executables = collect_executables(target_dir, file_hashes, only_paths=only_paths)

    print("\n========== SKAN VIRUSTOTAL ==========")
    if not executables:
        print("[INFO] Nie wykryto plikow wykonywalnych do sprawdzenia.")
        print("=====================================")
        return

    print(f"[INFO] Wykryto {len(executables)} plik(ow) wykonywalnych.")
    print(f"[INFO] Odpytuje VirusTotal (limit darmowego API: 4 zapytania / min).\n")

    cache = {}
    summary = {"clean": 0, "suspicious": 0, "malicious": 0, "unknown": 0, "error": 0}
    last_request_time = 0.0

    for idx, (rel_path, file_hash) in enumerate(executables, 1):
        print(f"[VT] ({idx}/{len(executables)}) {rel_path}")

        if file_hash in cache:
            result = cache[file_hash]
            print("      (wynik z cache hashu)")
        else:
            elapsed = time.monotonic() - last_request_time
            if last_request_time and elapsed < VT_REQUEST_INTERVAL_SEC:
                wait = VT_REQUEST_INTERVAL_SEC - elapsed
                print(f"      czekam {wait:.0f}s (rate limit)...")
                time.sleep(wait)

            result = query_virustotal(file_hash, api_key)
            last_request_time = time.monotonic()
            cache[file_hash] = result

        if result["status"] == "error":
            summary["error"] += 1
            print(f"      [BLAD] {result['message']}")
            if "401" in result["message"]:
                print("[BLAD] Przerywam skan - sprawdz poprawnosc klucza API.")
                break
            continue

        if result["status"] == "not_found":
            summary["unknown"] += 1
            print("      [INFO] Plik nieznany w bazie VirusTotal (brak raportu).")
            continue

        malicious = result["malicious"]
        suspicious = result["suspicious"]
        total_engines = (
            malicious + suspicious + result["harmless"]
            + result["undetected"] + result["timeout"]
        )

        if malicious > 0:
            summary["malicious"] += 1
            print(f"      [ALERT] ZLOSLIWY: {malicious}/{total_engines} silnikow wykrylo zagrozenie.")
        elif suspicious > 0:
            summary["suspicious"] += 1
            print(f"      [OSTRZEZENIE] Podejrzany: {suspicious}/{total_engines} silnikow.")
        else:
            summary["clean"] += 1
            print(f"      [OK] Czysty (0/{total_engines} wykryc).")

        if result.get("type_description"):
            print(f"      typ: {result['type_description']}")
        print(f"      raport: {VT_GUI_URL}{file_hash}")

    print("\n--- Podsumowanie skanu VirusTotal ---")
    print(f"  Czyste     : {summary['clean']}")
    print(f"  Podejrzane : {summary['suspicious']}")
    print(f"  Zlosliwe   : {summary['malicious']}")
    print(f"  Nieznane   : {summary['unknown']}")
    print(f"  Bledy      : {summary['error']}")
    print("=====================================")


def resolve_api_key(cli_value):
    if cli_value:
        return cli_value
    return os.environ.get("VT_API_KEY")


def create_baseline(target_dir, baseline_file, vt_api_key=None):
    print(f"[INFO] Tworzenie wzorca dla katalogu: {target_dir}")

    file_hashes = scan_directory(target_dir)

    baseline_data = {
        "metadata": {
            "root": os.path.abspath(target_dir),
            "created": datetime.now().isoformat(timespec="seconds"),
            "files_count": len(file_hashes),
        },
        "files": file_hashes,
    }

    try:
        with open(baseline_file, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f, indent=2, ensure_ascii=False)
    except (OSError, IOError) as e:
        print(f"[BLAD] Nie mozna zapisac wzorca do pliku {baseline_file}: {e}")
        sys.exit(1)

    print(f"[OK] Zapisano wzorzec: {baseline_file}")
    print(f"[OK] Liczba zindeksowanych plikow: {len(file_hashes)}")

    if vt_api_key:
        virustotal_scan(target_dir, file_hashes, vt_api_key)


def monitor_directory(target_dir, baseline_file, vt_api_key=None):
    print(f"[INFO] Monitorowanie katalogu: {target_dir}")
    print(f"[INFO] Wzorzec: {baseline_file}")

    try:
        with open(baseline_file, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)
    except FileNotFoundError:
        print(f"[BLAD] Nie znaleziono pliku wzorca: {baseline_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[BLAD] Plik wzorca jest uszkodzony (niepoprawny JSON): {e}")
        sys.exit(1)
    except (OSError, IOError) as e:
        print(f"[BLAD] Nie mozna odczytac pliku wzorca: {e}")
        sys.exit(1)

    baseline_hashes = baseline_data.get("files", {})
    current_hashes = scan_directory(target_dir)

    baseline_keys = set(baseline_hashes.keys())
    current_keys = set(current_hashes.keys())

    modified = []
    for path in baseline_keys & current_keys:
        if baseline_hashes[path] != current_hashes[path]:
            modified.append(path)

    deleted = sorted(baseline_keys - current_keys)
    added = sorted(current_keys - baseline_keys)
    modified.sort()

    print("\n========== RAPORT INTEGRALNOSCI ==========")
    print(f"Pliki we wzorcu : {len(baseline_keys)}")
    print(f"Pliki obecnie   : {len(current_keys)}")
    print("------------------------------------------")

    if not (modified or deleted or added):
        print("[OK] Brak zmian - integralnosc plikow zachowana.")
        print("==========================================")
    else:
        if modified:
            print(f"\n[ALERT] Zmodyfikowano {len(modified)} plik(ow):")
            for path in modified:
                print(f"  ~ {path}")
                print(f"      wzorzec : {baseline_hashes[path]}")
                print(f"      aktualny: {current_hashes[path]}")

        if deleted:
            print(f"\n[ALERT] Usunieto {len(deleted)} plik(ow):")
            for path in deleted:
                print(f"  - {path}")

        if added:
            print(f"\n[ALERT] Dodano {len(added)} nowy(ch) plik(ow):")
            for path in added:
                print(f"  + {path}")

        print("==========================================")

    if vt_api_key:
        suspicious_paths = set(modified) | set(added)
        if suspicious_paths:
            virustotal_scan(
                target_dir, current_hashes, vt_api_key,
                only_paths=suspicious_paths,
            )
        else:
            print("\n[INFO] Brak zmodyfikowanych/nowych plikow - skan VirusTotal pominiety.")


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor (FIM) - monitor integralnosci plikow oparty o SHA-256."
    )
    parser.add_argument(
        "mode",
        choices=["baseline", "monitor"],
        help="Tryb pracy: 'baseline' tworzy wzorzec, 'monitor' porownuje stan z wzorcem.",
    )
    parser.add_argument(
        "directory",
        help="Sciezka do katalogu poddawanego monitorowaniu.",
    )
    parser.add_argument(
        "-b", "--baseline-file",
        default="baseline.json",
        help="Sciezka do pliku JSON z wzorcem (domyslnie: baseline.json).",
    )
    parser.add_argument(
        "--virustotal",
        action="store_true",
        help="Skanuj pliki wykonywalne przez VirusTotal API (wymaga klucza API).",
    )
    parser.add_argument(
        "--vt-api-key",
        default=None,
        help="Klucz API VirusTotal. Mozna tez ustawic w zmiennej srodowiskowej VT_API_KEY.",
    )

    args = parser.parse_args()

    vt_api_key = None
    if args.virustotal:
        vt_api_key = resolve_api_key(args.vt_api_key)
        if not vt_api_key:
            print("[BLAD] Wlaczono --virustotal, ale brak klucza API.")
            print("       Podaj --vt-api-key <KLUCZ> lub ustaw zmienna srodowiskowa VT_API_KEY.")
            sys.exit(1)

    if args.mode == "baseline":
        create_baseline(args.directory, args.baseline_file, vt_api_key=vt_api_key)
    else:
        monitor_directory(args.directory, args.baseline_file, vt_api_key=vt_api_key)


if __name__ == "__main__":
    main()
