# File Integrity Monitor (FIM)

Prosty, lekki monitor integralności plików napisany w Pythonie. Skrypt rekurencyjnie skanuje wskazany katalog, oblicza sumy kontrolne **SHA-256** dla wszystkich plików i zapisuje je w pliku **JSON** jako wzorzec (baseline). Następnie potrafi porównać aktualny stan plików z zapisanym wzorcem i zgłosić alerty dla:

- plików **zmodyfikowanych** (`~`)
- plików **usuniętych** (`-`)
- plików **dodanych** (`+`)

## Spis treści

- [Funkcje](#funkcje)
- [Wymagania](#wymagania)
- [Instalacja](#instalacja)
- [Sposób użycia](#sposób-użycia)
  - [Tryb baseline](#tryb-baseline)
  - [Tryb monitor](#tryb-monitor)
- [Integracja z VirusTotal](#integracja-z-virustotal)
- [Format pliku wzorca](#format-pliku-wzorca)
- [Przykładowy raport](#przykładowy-raport)
- [Logika porównywania skrótów](#logika-porównywania-skrótów)
- [Obsługa błędów](#obsługa-błędów)
- [Ograniczenia](#ograniczenia)
- [Licencja](#licencja)

## Funkcje

- Dwa tryby działania: **baseline** (tworzenie wzorca) i **monitor** (porównanie).
- Algorytm haszujący **SHA-256** odporny na kolizje.
- Czytanie plików w blokach po 64 KB — działa nawet dla bardzo dużych plików.
- Ścieżki względne w pliku wzorca — łatwa przenośność między systemami.
- **Integracja z VirusTotal API v3** — automatyczne sprawdzanie reputacji plików wykonywalnych po hashu SHA-256 (bez wysyłania zawartości plików).
- Wykrywanie plików wykonywalnych po **rozszerzeniu** i **magic bytes** (PE/ELF/Mach-O/shebang).
- Tylko **biblioteki standardowe** Pythona — nie wymaga `pip install`.
- Odporność na błędy: brak uprawnień, błędy I/O, uszkodzony JSON, błędy sieci/API.

## Wymagania

- **Python 3.7+** (zalecany 3.10+)
- System operacyjny: Windows / Linux / macOS
- Brak zewnętrznych zależności — używane są tylko moduły standardowe:
  - `os`, `sys`, `json`, `time`, `hashlib`, `argparse`, `datetime`, `urllib`
- Dla integracji z VirusTotal: bezpłatny **klucz API** z [virustotal.com](https://www.virustotal.com/) (zob. [Integracja z VirusTotal](#integracja-z-virustotal)).

## Instalacja

```bash
git clone https://github.com/<twoja-nazwa>/file-integrity-monitor.git
cd file-integrity-monitor
```

Skrypt jest gotowy do użycia — nie wymaga dodatkowej konfiguracji.

## Sposób użycia

Składnia ogólna:

```bash
python fim.py <tryb> <katalog> [-b <plik_wzorca>]
```

| Argument | Opis | Domyślnie |
|---|---|---|
| `tryb` | `baseline` lub `monitor` | — (wymagane) |
| `katalog` | ścieżka do monitorowanego katalogu | — (wymagane) |
| `-b`, `--baseline-file` | ścieżka do pliku JSON z wzorcem | `baseline.json` |
| `--virustotal` | włącza skan plików wykonywalnych przez VirusTotal | wyłączone |
| `--vt-api-key` | klucz API VirusTotal (alternatywnie zmienna `VT_API_KEY`) | — |

### Tryb baseline

Tworzy plik wzorca z sumami kontrolnymi wszystkich plików w katalogu:

```bash
python fim.py baseline "C:\Dane\WaznyKatalog"
```

Z własną nazwą pliku wzorca:

```bash
python fim.py baseline "C:\Dane\WaznyKatalog" -b moj_wzorzec.json
```

**Linux / macOS:**

```bash
python3 fim.py baseline /etc/nginx -b nginx_baseline.json
```

### Tryb monitor

Porównuje aktualny stan katalogu z wcześniej utworzonym wzorcem:

```bash
python fim.py monitor "C:\Dane\WaznyKatalog"
```

Z własnym plikiem wzorca:

```bash
python fim.py monitor "C:\Dane\WaznyKatalog" -b moj_wzorzec.json
```

## Integracja z VirusTotal

Skrypt potrafi automatycznie sprawdzać reputację **plików wykonywalnych** w monitorowanym katalogu, korzystając z [VirusTotal API v3](https://docs.virustotal.com/reference/file-info). Zapytania używają już obliczonego skrótu **SHA-256**, więc **zawartość plików nigdy nie opuszcza Twojego komputera** — wysyłany jest wyłącznie hash.

### Jak zdobyć klucz API (darmowy)

1. Załóż konto na [virustotal.com](https://www.virustotal.com/) (Sign up).
2. Kliknij awatar w prawym górnym rogu → **API key**.
3. Skopiuj klucz (~64 znaki).
4. Limity darmowego planu: **4 zapytania / minutę**, **500 / dzień** — skrypt sam pilnuje throttlingu (15 s przerwy między zapytaniami) i cache'uje wyniki po hashu w obrębie jednego uruchomienia.

### Jak wykrywane są pliki wykonywalne

| Metoda | Przykłady |
|---|---|
| Rozszerzenie | `.exe`, `.dll`, `.sys`, `.scr`, `.com`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.msi`, `.jar`, `.sh`, `.bin`, `.elf`, `.so`, `.dylib`, `.app`, `.dmg`, `.apk` |
| Magic bytes nagłówka | `MZ` (PE/Windows), `\x7FELF` (Linux), Mach-O (macOS), `#!` (skrypty z shebangiem) |

Plik trafia do skanu, jeśli pasuje do **dowolnego** z powyższych — łapie też pliki bez rozszerzenia (np. natywne binarki na Linuksie).

### Kiedy odpalany jest skan

| Tryb | Co jest skanowane |
|---|---|
| `baseline --virustotal` | **Wszystkie** wykonywalne pliki w katalogu (snapshot reputacji w momencie tworzenia wzorca). |
| `monitor --virustotal` | Tylko pliki **zmodyfikowane** lub **dodane** od czasu wzorca — żeby oszczędzać limit API. |

### Przykłady użycia

Klucz przez argument linii poleceń:

```bash
python fim.py baseline "C:\Dane\WaznyKatalog" --virustotal --vt-api-key TWOJ_KLUCZ
```

Klucz przez zmienną środowiskową (zalecane — nie zostaje w historii powłoki):

**Windows PowerShell:**

```powershell
$env:VT_API_KEY = "TWOJ_KLUCZ"
python fim.py monitor "C:\Dane\WaznyKatalog" --virustotal
```

**Linux / macOS:**

```bash
export VT_API_KEY="TWOJ_KLUCZ"
python3 fim.py monitor /etc/nginx --virustotal
```

### Przykładowy fragment raportu VirusTotal

```
========== SKAN VIRUSTOTAL ==========
[INFO] Wykryto 3 plik(ow) wykonywalnych.
[INFO] Odpytuje VirusTotal (limit darmowego API: 4 zapytania / min).

[VT] (1/3) bin/putty.exe
      [OK] Czysty (0/72 wykryc).
      typ: Win32 EXE
      raport: https://www.virustotal.com/gui/file/<sha256>
[VT] (2/3) tools/suspicious.exe
      [ALERT] ZLOSLIWY: 47/72 silnikow wykrylo zagrozenie.
      typ: Win32 EXE
      raport: https://www.virustotal.com/gui/file/<sha256>
[VT] (3/3) scripts/install.ps1
      [INFO] Plik nieznany w bazie VirusTotal (brak raportu).

--- Podsumowanie skanu VirusTotal ---
  Czyste     : 1
  Podejrzane : 0
  Zlosliwe   : 1
  Nieznane   : 1
  Bledy      : 0
=====================================
```

### Bezpieczeństwo

- **Hash zamiast pliku** — VirusTotal otrzymuje wyłącznie `SHA-256`, nigdy treści.
- **Klucz API nie jest nigdzie zapisywany** przez skrypt — żyje tylko w pamięci procesu.
- Status `nieznany` (`404 Not Found`) oznacza, że plik nie był jeszcze skanowany przez VirusTotal — to normalne dla świeżo skompilowanych binarek lub plików własnej produkcji.

## Format pliku wzorca

Plik wzorca to standardowy JSON o następującej strukturze:

```json
{
  "metadata": {
    "root": "C:\\Dane\\WaznyKatalog",
    "created": "2026-04-27T18:30:00",
    "files_count": 42
  },
  "files": {
    "dokument.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "podkatalog/skrypt.py": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
  }
}
```

- `metadata.root` — bezwzględna ścieżka katalogu w momencie tworzenia wzorca.
- `metadata.created` — znacznik czasu utworzenia w formacie ISO 8601.
- `metadata.files_count` — liczba zindeksowanych plików.
- `files` — mapa: **ścieżka względna** → **skrót SHA-256**.

## Przykładowy raport

```
[INFO] Monitorowanie katalogu: C:\Dane\WaznyKatalog
[INFO] Wzorzec: baseline.json

========== RAPORT INTEGRALNOSCI ==========
Pliki we wzorcu : 42
Pliki obecnie   : 43
------------------------------------------

[ALERT] Zmodyfikowano 1 plik(ow):
  ~ konfiguracja.ini
      wzorzec : 5d41402abc4b2a76b9719d911017c592...
      aktualny: 7c4a8d09ca3762af61e59520943dc265...

[ALERT] Usunieto 1 plik(ow):
  - stary_log.txt

[ALERT] Dodano 2 nowy(ch) plik(ow):
  + nowy_dokument.docx
  + tymczasowy.tmp
==========================================
```

## Logika porównywania skrótów

Algorytm porównywania działa w czterech krokach:

1. **Wczytanie wzorca** — słownik `ścieżka → SHA-256` z pliku JSON.
2. **Skan bieżącego stanu** — taki sam słownik dla aktualnej zawartości katalogu.
3. **Operacje na zbiorach kluczy:**
   - **część wspólna** + różny skrót → plik **zmodyfikowany**
   - **tylko we wzorcu** → plik **usunięty**
   - **tylko w bieżącym** → plik **dodany**
4. **Wniosek:** SHA-256 jest funkcją deterministyczną i odporną na kolizje, więc identyczne skróty oznaczają identyczną zawartość bajtową pliku, a różne — pewną modyfikację treści.

## Obsługa błędów

Skrypt został zaprojektowany tak, aby nie przerywał pracy przy typowych problemach:

| Sytuacja | Reakcja |
|---|---|
| Brak uprawnień do pliku | `[OSTRZEZENIE]` + pominięcie pliku, kontynuacja |
| Błąd `OSError` / `IOError` przy odczycie | `[OSTRZEZENIE]` + pominięcie pliku |
| Brak dostępu do podkatalogu (`os.walk`) | logowane przez handler `onerror` |
| Brak pliku wzorca | `[BLAD]` + zakończenie z kodem 1 |
| Uszkodzony JSON wzorca | `[BLAD]` z opisem błędu parsowania |
| Nieprawidłowa ścieżka katalogu | walidacja przez `os.path.isdir` + `[BLAD]` |
| Brak klucza API VT przy `--virustotal` | `[BLAD]` + zakończenie z kodem 1 |
| Nieprawidłowy klucz API (HTTP 401) | `[BLAD]` + przerwanie skanu VT, reszta raportu kontynuowana |
| Przekroczony limit API (HTTP 429) | `[BLAD]` w raporcie VT dla danego pliku, kontynuacja |
| Brak internetu / timeout | `[BLAD]` z opisem błędu połączenia, kontynuacja |

## Ograniczenia

- Skrypt monitoruje **wyłącznie zawartość plików** — nie śledzi zmian uprawnień, właściciela ani znaczników czasu.
- Pliki, do których nie ma uprawnień odczytu, są pomijane (z ostrzeżeniem) i **nie pojawią się** w wzorcu ani w raporcie.
- Dowiązania symboliczne są podążane przez `os.walk` — w skrajnych przypadkach (cykle) może to powodować redundantne skanowanie.
- Plik wzorca powinien być przechowywany w bezpiecznym miejscu (np. tylko do odczytu) — atakujący ze świeżymi uprawnieniami zapisu mógłby go nadpisać.
- Skan VirusTotal opiera się na **reputacji hashu** — modyfikacja choćby jednego bajtu zmienia SHA-256 i taki plik będzie nieznany w bazie VT (status `nieznany`), nawet jeśli pierwotnie był złośliwy. Status `czysty` z VT nie jest gwarancją bezpieczeństwa — to tylko brak wykryć w danym momencie.

## Licencja

MIT — zobacz plik `LICENSE` (jeśli dołączony).
