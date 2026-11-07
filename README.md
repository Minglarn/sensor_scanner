# SensorScanner

**Version:** `2026.11.07.12` (CalVer)  
**Container Image:** `ghcr.io/minglarn/sensor_scanner:latest`  
**GitHub Repository:** `https://github.com/Minglarn/sensor_scanner`

**SensorScanner** är en nyckelfärdig, Dockeriserad helhetslösning som använder `rtl_433` tillsammans med en **RTL-SDR Blog V4**-mottagare (R828D-tuner) på **433.92 MHz** och **868.3 MHz** parallellt med värdmaskinens **Bluetooth Low Energy (BLE 2.4 GHz)**-adapter (`BlueZ` via D-Bus) för att avlyssna, avkoda, lagra, filtrera och vidarebefordra trådlösa RF- och BLE-signaler.

Applikationen fångar automatiskt upp vädersensorer, el- och vattenmätare, däcktryckssensorer (TPMS), fjärrkontroller, dörr-/fönstersensorer samt rörelsedetektorer och presenterar dem i realtid via ett responsivt webbgränssnitt, lagrar historik i SQLite (WAL-läge) och publicerar utvalda enheter till MQTT inklusive stöd för **Home Assistant MQTT Auto-Discovery**.

---

## Funktioner i korthet

- **Inbyggt stöd för RTL-SDR Blog V4:** Multi-stage `Dockerfile` som kompilerar `rtl-sdr-blog`-drivrutinen (`-DDETACH_KERNEL_DRIVER=ON`) samt senaste `rtl_433` direkt från källkod.
- **Dynamisk frekvensstyrning i realtid:** Växla direkt i webbgränssnittet mellan:
  - `433`: Fast lyssning på `433.92 MHz`
  - `868`: Fast lyssning på `868.3 MHz` (`-s 1024k`)
  - `hop`: Dual-Band som automatiskt hoppar mellan `433.92 MHz` och `868.3 MHz` var 60:e sekund
  - `custom`: Egna frekvenslistor, sample rate och hopp-intervall
- **Smart Debounce-filter:** Filtrerar bort identiska dubblettpaket (vanligt när sensorer sänder samma paket 3-8 gånger inom 500 ms) innan de når SQLite och MQTT.
- **Enhetsregister & Svartlistning:** Sätt egna alias och kategorier på dina sensorer, aktivera/inaktivera MQTT per enhet eller svartlista/ignorera grannars sensorer och förbipasserande bilars TPMS.
- **Home Assistant Auto-Discovery:** Skicka färdiga MQTT Discovery-konfigurationer till Home Assistant med ett enda klick per enhet.
- **Självläkande Watchdog & Diagnostik:** Om USB-stickan tappar kontakten startar `rtl_manager.py` automatiskt om processen var 5:e sekund och strömmar `stderr`-loggen i realtid till webbgränssnittet.

---

## 1. Förbered värdmaskinen (Linux DVB-T Blacklist)

På Linux-baserade värdmaskiner (Ubuntu, Debian, Raspberry Pi OS, Proxmox LXC/Host m.fl.) laddar kärnan ofta automatiskt in TV-drivrutinen `dvb_usb_rtl28xxu` när du ansluter en RTL-SDR-sticka. Även om SensorScanner kompileras med `-DDETACH_KERNEL_DRIVER=ON` rekommenderas det starkt att svartlista kärnmodulen på värdmaskinen för stabil drift.

Kör följande kommandon på värdmaskinen:

```bash
# 1. Skapa blacklist-fil för DVB-T-kärnmoduler
sudo tee /etc/modprobe.d/blacklist-rtlsdr.conf <<EOF
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
blacklist dvb_usb_v2
blacklist r820t
EOF

# 2. Ladda ur modulerna om de redan är aktiva
sudo modprobe -r dvb_usb_rtl28xxu rtl2832 rtl2830 dvb_usb_v2 || true

# 3. Uppdatera initramfs
sudo update-initramfs -u
```

Koppla därefter ur och sätt tillbaka RTL-SDR V4-stickan i USB-porten.

---

## 2. Hitta eller ändra serienummer på RTL-SDR V4 (`rtl_eeprom`)

Om du har flera USB-mottagare anslutna till samma dator (t.ex. en för 433/868 MHz och en för ADS-B/1090 MHz) kan du låsa `SensorScanner` till rätt sticka genom att ange antingen enhetsindex (`0`, `1`, `2`) eller ett 8-siffrigt serienummer i `DEVICE_INDEX`.

Eftersom `rtl_test` och `rtl_eeprom` är förinstallerade i `SensorScanner`-containern kan du köra dem direkt via Docker utan att installera verktyg på värdmaskinen:

### Lista anslutna RTL-SDR-stickor och deras serienummer
```bash
docker run --rm -it --device /dev/bus/usb:/dev/bus/usb ghcr.io/minglarn/sensor_scanner:latest rtl_test -t
```

### Läsa nuvarande EEPROM-information på sticka 0
```bash
docker run --rm -it --device /dev/bus/usb:/dev/bus/usb ghcr.io/minglarn/sensor_scanner:latest rtl_eeprom -d 0
```

### Sätta ett nytt unikt 8-siffrigt serienummer (t.ex. `00000433`)
*(Stoppa `sensor_scanner` först om containern redan körs: `docker compose stop`)*
```bash
docker run --rm -it --device /dev/bus/usb:/dev/bus/usb ghcr.io/minglarn/sensor_scanner:latest rtl_eeprom -d 0 -s 00000433
```
Bekräfta med `y` när `rtl_eeprom` frågar och koppla sedan ur och in USB-stickan. Därefter kan du sätta `DEVICE_INDEX=00000433` i `docker-compose.yml` eller direkt i webbgränssnittet under **System & Logg**.

---

## 3. Snabbstart med Docker Compose

Skapa en mapp för projektet och spara `docker-compose.yml`:

```yaml
services:
  sensor_scanner:
    image: ghcr.io/minglarn/sensor_scanner:latest
    # build: .
    container_name: sensor_scanner
    restart: unless-stopped
    ports:
      - "8085:8080"
    devices:
      - /dev/bus/usb:/dev/bus/usb
    volumes:
      - ./data:/app/data
    environment:
      - TZ=Europe/Stockholm
      - DEVICE_INDEX=0
      - DEFAULT_MODE=hop
      - RTL_GAIN=auto
      - RTL_PPM=0
      - MQTT_HOST=192.168.1.121
      - MQTT_PORT=1883
      - MQTT_USER=
      - MQTT_PASS=
      - MQTT_PREFIX=sensor_scanner
      - RETENTION_DAYS=30
```

Starta containern i bakgrunden:

```bash
docker compose up -d
```

Öppna sedan webbgränssnittet i din webbläsare på:
```text
http://<DIN-SERVER-IP>:8085
```

---

## 4. Miljövariabler

Alla miljövariabler används som standardvärden första gången databasen skapas. Därefter kan alla inställningar ändras live i webbgränssnittet under fliken **System & Logg** och sparas permanent i `/app/data/sensor_scanner.db`.

| Variabel | Standardvärde | Beskrivning |
| :--- | :--- | :--- |
| `TZ` | `Europe/Stockholm` | Tidszon för tidsstämplar och daglig rensning. |
| `DEVICE_INDEX` | `0` | Enhetsindex (`0`, `1`) eller 8-siffrigt RTL-SDR-serienummer. |
| `DEFAULT_MODE` | `hop` | Startläge: `433`, `868`, `hop` eller `custom`. |
| `RTL_GAIN` | `auto` | Tuner gain (`auto` eller specifikt dB-värde, t.ex. `40.2`). |
| `RTL_PPM` | `0` | Frekvenskorrigering i PPM. |
| `MQTT_HOST` | `192.168.1.121` | IP-adress eller värdnamn till din MQTT-broker. |
| `MQTT_PORT` | `1883` | Port för MQTT-broker. |
| `MQTT_USER` | *(tom)* | Användarnamn för MQTT-autentisering (valfritt). |
| `MQTT_PASS` | *(tom)* | Lösenord för MQTT-autentisering (valfritt). |
| `MQTT_PREFIX` | `sensor_scanner` | Bas-topic för publicerade meddelanden. |
| `RETENTION_DAYS` | `30` | Antal dagar som historik i `signals`-tabellen sparas. |

---

## 5. MQTT-struktur & Home Assistant Auto-Discovery

När en signal tas emot från en enhet där `mqtt_enabled = 1` och `ignored = 0` publiceras rå JSON till:

- `<MQTT_PREFIX>/<model>/<device_id>` (t.ex. `sensor_scanner/Fineoffset-WH2/142`)
- `<MQTT_PREFIX>/alias/<alias>` (om ett eget alias har angivits, t.ex. `sensor_scanner/alias/Vaxthus_Temp`)
- `<MQTT_PREFIX>/status` (`online` / `offline` via LWT)

Klickar du på knappen **HA Discovery** på en enhet i webbgränssnittet skickas automatiskt retainade konfigurationspaket till:
- `homeassistant/sensor/sensor_scanner_<device_key>_<metric>/config`

Home Assistant skapar då omedelbart enheten med tillhörande sensorer (temperatur, luftfuktighet, batteristatus, däcktryck, effekt/energi, RSSI och SNR).

---

## 6. REST API-översikt

| Metod | Endpoint | Beskrivning |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Hämtar status för `rtl_433`, aktivt frekvensläge, kommandorad, `stderr`, statistik och MQTT-status. |
| `POST` | `/api/control` | Byter frekvensläge (`433`, `868`, `hop`, `custom`), ändrar gain/ppm eller startar om `rtl_433`. |
| `GET` | `/api/signals` | Sökbar och filtrerbar historik (`search`, `model`, `device_id`, `freq_band`, `only_aliased`, `limit`, `offset`). |
| `GET` | `/api/models` | Listar alla unika protokoll/modeller som upptäckts. |
| `GET` | `/api/devices` | Listar alla registrerade enheter i enhetsregistret. |
| `GET` | `/api/devices/{device_key}` | Hämtar en specifik enhet samt dess 20 senaste mätvärden. |
| `PUT` | `/api/devices/{device_key}` | Uppdaterar `alias`, `category`, `mqtt_enabled` och `ignored`. |
| `POST` | `/api/devices/{device_key}/ha_discovery` | Skickar Home Assistant MQTT Auto-Discovery för enheten. |
| `DELETE` | `/api/devices/{device_key}` | Raderar enheten och all dess signalhistorik. |
| `GET` | `/api/settings` | Läser samtliga systeminställningar från SQLite. |
| `PUT` | `/api/settings` | Uppdaterar systeminställningar och startar om SDR/MQTT vid behov. |
| `GET` | `/api/stats` | Returnerar 24h-statistik per timme, bandfördelning 433 vs 868 MHz samt topp 10 mest aktiva enheter. |
| `WS` | `/ws` | WebSocket-ström för realtidssignaler, statusuppdateringar och `stderr`-diagnostik. |

