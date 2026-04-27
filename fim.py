import os
import sys
import json
import hashlib
import argparse
from datetime import datetime


CHUNK_SIZE = 64 * 1024


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


def create_baseline(target_dir, baseline_file):
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


def monitor_directory(target_dir, baseline_file):
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
        return

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

    args = parser.parse_args()

    if args.mode == "baseline":
        create_baseline(args.directory, args.baseline_file)
    else:
        monitor_directory(args.directory, args.baseline_file)


if __name__ == "__main__":
    main()
