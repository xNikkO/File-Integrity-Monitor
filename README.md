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
- Tylko **biblioteki standardowe** Pythona — nie wymaga `pip install`.
- Odporność na błędy: brak uprawnień, błędy I/O, uszkodzony JSON.

## Wymagania

- **Python 3.7+** (zalecany 3.10+)
- System operacyjny: Windows / Linux / macOS
- Brak zewnętrznych zależności — używane są tylko moduły standardowe:
  - `os`, `sys`, `json`, `hashlib`, `argparse`, `datetime`

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

### Tryb baseline

Tworzy plik wzorca z sumami kontrolnymi wszystkich plików w katalogu:

```bash
python fim.py baseline "C:\Users\adamm\Documents\WaznyKatalog"
```

Z własną nazwą pliku wzorca:

```bash
python fim.py baseline "C:\Users\adamm\Documents\WaznyKatalog" -b moj_wzorzec.json
```

**Linux / macOS:**

```bash
python3 fim.py baseline /etc/nginx -b nginx_baseline.json
```

### Tryb monitor

Porównuje aktualny stan katalogu z wcześniej utworzonym wzorcem:

```bash
python fim.py monitor "C:\Users\adamm\Documents\WaznyKatalog"
```

Z własnym plikiem wzorca:

```bash
python fim.py monitor "C:\Users\adamm\Documents\WaznyKatalog" -b moj_wzorzec.json
```

## Format pliku wzorca

Plik wzorca to standardowy JSON o następującej strukturze:

```json
{
  "metadata": {
    "root": "C:\\Users\\adamm\\Documents\\WaznyKatalog",
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
[INFO] Monitorowanie katalogu: C:\Users\adamm\Documents\WaznyKatalog
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

## Ograniczenia

- Skrypt monitoruje **wyłącznie zawartość plików** — nie śledzi zmian uprawnień, właściciela ani znaczników czasu.
- Pliki, do których nie ma uprawnień odczytu, są pomijane (z ostrzeżeniem) i **nie pojawią się** w wzorcu ani w raporcie.
- Dowiązania symboliczne są podążane przez `os.walk` — w skrajnych przypadkach (cykle) może to powodować redundantne skanowanie.
- Plik wzorca powinien być przechowywany w bezpiecznym miejscu (np. tylko do odczytu) — atakujący ze świeżymi uprawnieniami zapisu mógłby go nadpisać.

## Licencja

MIT — zobacz plik `LICENSE` (jeśli dołączony).

---

**Autor:** *NikkO*
