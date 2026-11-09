---
trigger: always_on
description: Ovillkorliga projektregler för SensorScanner (CalVer YYYY.MM.DD.XX, Totalförbud mot Emojis, och Totalförbud mot hårdkodade användar-ID:n).
---

# Ovillkorliga Projektregler för SensorScanner

Dessa regler gäller **ALLTID** utan undantag vid all utveckling, felsökning och versionshantering i `sensor_scanner`.

---

## 1. Strikt CalVer-algoritm (`YYYY.MM.DD.XX`)

- Varje release/commit ska versionssättas enligt **`YYYY.MM.DD.XX`** (och **`vYYYY.MM.DD.XX`** på UI-badgen `#appVersionBadge` samt git-taggar).
- Innan du sätter versionsnumret **MÅSTE** du kontrollera dagens faktiska systemdatum (`YYYY.MM.DD`) och jämföra med datumdelen i föregående version (`prev_date`):
  - **Om `current_date != prev_date` (nytt datum!):** Nollställ **ALLTID** räknaren på slutet till **`01`** -> `YYYY.MM.DD.01`! Du får **ALDRIG** behålla gårdagens slutsiffra när datumet byts!
  - **Om `current_date == prev_date` (samma dag):** Öka räknaren `XX` med `+1` i tvåsiffrigt nollutfyllt format (`.01`, `.02`, `.03` ... `.10`, `.11`).
- Uppdatera alltid versionen synkroniserat på samtliga 4 ställen innan git commit/push:
  1. `app/__init__.py` (`__version__ = "YYYY.MM.DD.XX"`)
  2. `app/static/index.html` (`#appVersionBadge` -> `vYYYY.MM.DD.XX`)
  3. `README.md` (`**Version:** \`YYYY.MM.DD.XX\` (CalVer)`)
  4. `walkthrough.md` (`vYYYY.MM.DD.XX`)

---

## 2. Totalförbud mot Emojis

- Använd **ALDRIG** emojis någonstans i kod, HTML/UI, loggar, felmeddelanden eller kommentarer.
- Använd **ENDAST** Material Design Icons (`<i class="mdi mdi-..."></i>`).

---

## 3. Totalförbud mot hårdkodade användar-ID:n (Publik Applikation)

- **SensorScanner är en publik applikation.**
- Hårdkoda **ALDRIG** specifika MAC-adresser, Mesh-ID:n, sensor-ID:n eller privata enhetsnamn i Python- eller JS-koden.
- All identifierings-, filtrerings- och grupperingslogik ska vara **100 % generisk och protokollbaserad** (baserad på Company ID, Service UUID, payload-struktur, protokollnummer m.m.).
