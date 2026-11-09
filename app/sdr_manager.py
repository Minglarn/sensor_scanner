"""SDR / rtl_433 Subprocess, Wideband 868 MHz (1024k), Wireless M-Bus & Protocol Lookup Manager."""

import asyncio
import collections
import hashlib
import json
import logging
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Tuple

from app.database import extract_device_id, extract_freq_mhz

logger = logging.getLogger("sensor_scanner.sdr")

PROTOCOL_LINE_RE = re.compile(r"^\s*\[(\d+)\]\*?\s+(.+)$")
TUNED_TO_RE = re.compile(r"Tuned to\s+([0-9.]+)\s*MHz", re.IGNORECASE)

# Wideband 868/869 MHz center frequencies:
# - With -s 1024k (1.024 MS/s): 868.60M covers 868.08 - 869.12 MHz (868.30 MHz + 868.95 MHz wM-Bus)
# - With -s 2048k (2.048 MS/s): 868.90M covers 867.88 - 869.92 MHz (868.30 + 868.95 + 869.525 MHz in 1 sweep!)
# - On 433.92M with -s 1024k/2048k: covers 433.40 - 434.44 MHz (433.42 MHz Somfy RTS + 433.92 MHz OOK/FSK)
WIDEBAND_868_RTL_FREQ = "868.60M"
WIDEBAND_868_DISPLAY = "868.30 / 868.95 MHz"
WIDEBAND_868_2048K_RTL_FREQ = "868.90M"
WIDEBAND_868_2048K_DISPLAY = "868.30–869.52 MHz"
VHF_WMBUS_169_RTL_FREQ = "169.4375M"
VHF_WMBUS_169_DISPLAY = "169.44 MHz"
DEFAULT_SAMPLE_RATE = "1024k"
VALID_SDR_MODES = ("433", "868", "hop", "hop_eu", "hop_global", "custom")

WMBUS_AND_METER_PROTOCOLS = {
    36,
    43,
    44,
    45,
    63,
    81,
    83,
    104,
    105,
    106,
    107,
    117,
    130,
    136,
    149,
    154,
    168,
    176,
    188,
    223,
    224,
    228,
    234,
    235,
    237,
    238,
    239,
    255,
}

WMBUS_AND_METER_MODEL_KEYWORDS: Tuple[str, ...] = (
    "wireless-mbus",
    "wmbus",
    "kamstrup",
    "sensus",
    "itron",
    "diehl",
    "mueller",
    "beters",
    "bmeters",
    "apator",
    "zenner",
    "qundis",
    "techem",
    "landis",
    "aidon",
    "sharky",
    "multical",
    "flowiq",
    "hydrus",
    "iperl",
    "badger",
    "neptune",
    "flowis",
    "qcaloric",
    "qwater",
    "ultramess",
    "engelmann",
    "allmess",
    "minol",
    "ista",
    "sparsnas",
    "efergy",
    "owl",
    "cm180",
    "meter",
    "energy",
    "water",
    "emon",
    "gas",
)

WMBUS_AND_METER_PAYLOAD_KEYS = {
    "total_water_m3",
    "water_m3",
    "volume_m3",
    "total_volume_m3",
    "flow_m3h",
    "flow_lph",
    "max_flow_m3h",
    "total_energy_kwh",
    "energy_kwh",
    "total_heat_kwh",
    "heat_kwh",
    "water_temp_c",
    "flow_temp_c",
    "return_temp_c",
    "meter_type",
    "cumulative_kwh",
    "total_kwh",
    "energy_mwh",
    "power_w",
    "power_kw",
    "calculated_power_w",
    "effect",
    "pulses",
    "pulse_count",
}

VOLATILE_KEYS = {
    "time",
    "rssi",
    "snr",
    "noise",
    "freq",
    "freq1",
    "freq2",
    "mod",
    "mic",
    "protocol_name",
    "protocol_full_name",
}

# Curated human-readable protocol catalog for rtl_433 (#1 - #265+)
RTL433_PROTOCOLS: Dict[int, str] = {
    1: "Silvercrest Remote Control",
    2: "Rubicson / TFA 30.3197 Temp Sensor",
    3: "Prologue / Kedsum Temp/Hygro",
    4: "Waveman Switch Transmitter",
    6: "ELV EM 1000",
    7: "ELV WS 2000",
    8: "LaCrosse TX Temp/Hygro",
    10: "Acurite 896 Rain Gauge",
    11: "Acurite 609TXC Temp/Hygro",
    12: "Oregon Scientific Weather Sensor",
    13: "Mebus 433",
    14: "Intertechno 433",
    15: "KlikAanKlikUit Wireless Switch",
    16: "AlectoV1 Weather Sensor",
    17: "Cardin S466-TX2",
    18: "Fine Offset Electronics WH2/WH5",
    19: "Nexus / FreeTec / TFA Temp/Hygro",
    20: "Ambient Weather F007TH / TFA",
    21: "Calibeur RF-104 Sensor",
    22: "X10 RF",
    23: "DSC Security Contact",
    24: "Brennenstuhl RCS 2044",
    25: "Globaltronics GT-WT-02 Sensor",
    26: "Danfoss CFR Thermostat",
    29: "Chuango Security Technology",
    30: "Generic Remote SC226x EV1527",
    31: "TFA-Twin-Plus-30.3049 / Conrad KW9010",
    32: "Bresser Thermo-/Hygro-Sensor 3CH",
    33: "WT450 / WT260H Temp/Hygro",
    34: "LaCrosse WS-2310 / WS-3600 Weather",
    35: "Esperanza EWS",
    36: "Efergy e2 Classic",
    37: "Inovalley kw9015b Temp/Rain",
    38: "Generic Temp Sensor 1",
    39: "WG-PB12V1 Temperature Sensor",
    40: "Acurite 592TXR Temp/Hygro",
    41: "Acurite 986 Refrigerator / Freezer",
    42: "HIDEKI TS04 Temp/Hygro/Wind/Rain",
    43: "Watchman Sonic / Apollo Ultrasonic",
    44: "CurrentCost Current Sensor",
    45: "emonTx OpenEnergyMonitor",
    46: "HT680 Remote Control",
    47: "Conrad S3318P Temp/Hygro",
    48: "Akhan 100F14 Remote Keyless Entry",
    49: "Quhwa Wireless Doorbell",
    50: "OSv1 Temperature Sensor",
    51: "Proove / Nexa / KlikAanKlikUit Switch",
    52: "Bresser 5-in-1 Weather Station",
    53: "Springfield Temp & Soil Moisture",
    54: "Oregon Scientific SL109H Temp/Hygro",
    55: "Acurite 606TX Temp Sensor",
    56: "TFA Pool Temperature Sensor",
    57: "Kedsum Temp & Humidity Sensor",
    58: "Blyss DC5-UK-WH",
    59: "Steelmate TPMS",
    60: "Schrader TPMS",
    61: "LightwaveRF",
    62: "Elro DB286A Doorbell",
    63: "Efergy Optical",
    64: "Honda Remote Key",
    67: "Radiohead ASK",
    68: "Kerui PIR / Contact Sensor",
    69: "Fine Offset WH1050 Weather Station",
    70: "Honeywell Door/Window Sensor",
    71: "Maverick ET-732/733 BBQ Sensor",
    72: "RF-tech",
    73: "LaCrosse TX141TH-Bv2",
    74: "Acurite 00275rm/00276rm Temp/Hygro",
    75: "LaCrosse TX35DTH-IT / TFA 30.3155",
    76: "LaCrosse TX29IT / TFA 30.3159.IT",
    77: "Vaillant calorMatic VRT340f",
    78: "Fine Offset WH24 / WH65B Weather Station",
    79: "Fine Offset WH0530 Temp/Rain",
    80: "IBIS Beacon",
    81: "Oil Ultrasonic Standard FSK",
    82: "Citroen TPMS",
    83: "Oil Ultrasonic Standard ASK",
    84: "Thermopro TP11 Thermometer",
    85: "Solight TE44 / TE66 Temp",
    86: "Wireless Smoke & Heat Detector GS 558",
    87: "Generic Wireless Motion Sensor",
    88: "Toyota TPMS",
    89: "Ford TPMS",
    90: "Renault TPMS",
    91: "inFactory NC-3982 Temp/Hygro",
    92: "FT-004-B Temperature Sensor",
    93: "Ford Car Key",
    94: "Philips Outdoor Temperature Sensor",
    95: "Schrader TPMS EG53MA4",
    96: "Nexa / Proove Self-Learning Switch",
    97: "Thermopro TP08/TP12/TP20 Thermometer",
    98: "GE Color Effects",
    99: "X10 Security",
    100: "Interlogix GE UTC Security Devices",
    101: "Dish Remote 6.3",
    102: "SimpliSafe Home Security",
    103: "Sensible Living Mini-Plant Moisture",
    104: "Wireless M-Bus (EN 13757-4 Vatten/Värme/El)",
    105: "Wireless M-Bus Mode S (EN 13757-4)",
    106: "Wireless M-Bus Mode R (EN 13757-4)",
    107: "Wireless M-Bus Mode F (EN 13757-4)",
    108: "Hyundai WS SENZOR77 Temp/Hygro",
    109: "WT0124 Pool Thermometer",
    110: "PMV-107J (Toyota) TPMS",
    111: "Emos TTX201 Temp Sensor",
    112: "Ambient Weather F007TH",
    113: "Ambient Weather TX-8300",
    114: "Maverick ET-73",
    115: "Honeywell ActivLink Doorbell",
    116: "Honeywell ActivLink Doorbell (FSK)",
    117: "ESA1000 / ESA2000 Energy Monitor",
    118: "Biltema Rain Gauge",
    119: "Bresser Weather Center 5-in-1",
    120: "Digitech XC-0324 / AmbientPod",
    121: "Opus/Imagintronix XT300 Soil Moisture",
    122: "FS20",
    123: "Jansite TPMS",
    124: "LaCrosse/ELV/Conrad WS7000",
    125: "TS-FT002 Tank Liquid Level",
    126: "Companion WTR001 Temp Sensor",
    127: "Ecowitt WH53 / WH0280 / WH0281A",
    128: "DirecTV RC66RX Remote Control",
    129: "Eurochron Temp/Hygro Sensor",
    130: "IKEA Sparsnäs Energy Meter",
    131: "Microchip HCS200/HCS300 KeeLoq",
    132: "TFA Dostmann 30.3196 T/H",
    133: "Rubicson 48659 Pool Thermometer",
    134: "AOK Weather Station",
    135: "Philips AJ3650 Awaken",
    136: "ESIC EMT7110 Power Meter",
    137: "Globaltronics QUIGG GT-TMBBQ-05",
    138: "Globaltronics GT-WT-03 Sensor",
    139: "Norgo NGE101",
    140: "Hyundai / Elantra2012 TPMS",
    141: "Auriol HG02832 / Rubicson",
    142: "Fine Offset WH32 / EcoWitt",
    143: "Holman Industries iWeather WS5029",
    144: "TBH Weather Sensor",
    145: "WS2032 Weather Station",
    146: "Auriol AFW2A1 Temp/Hygro",
    147: "TFA Drop Rain Gauge 30.3233.01",
    148: "DSC Security Contact (WS4945)",
    149: "ERT Standard Consumption Message",
    150: "Klimalogg Pro",
    151: "Visonic Powercode",
    152: "Microchip HCS200/HCS300 KeeLoq",
    153: "Cotech 36-7959 / SwitchDoc FT020T",
    154: "Standard Consumption Message Plus",
    155: "Fine Offset WH1080/WH3080 (FSK)",
    156: "Abarth 124 Spider / TPMS",
    157: "Missil ML0757 Weather Station",
    158: "Sharp SPC775 Weather Station",
    159: "Insteon",
    160: "Schrader TPMS SMD3MA4 (Subaru)",
    161: "FS20 / FHT",
    162: "ThermoPro-TX2 Temp Sensor",
    163: "Acurite 590TX Temp/Hygro",
    164: "Security+ 2.0 (Keyfob)",
    165: "TFA Dostmann 30.3221.02 T/H",
    166: "LaCrosse View LTV-WSDTH01",
    167: "Somfy RTS",
    168: "IKEA Sparsnäs Energy Monitor",
    169: "Nice Flor-s Remote Control",
    170: "LaCrosse View LTV-WR1",
    171: "LaCrosse View LTV-TH",
    172: "Bresser 6-in-1 Weather Station",
    173: "Bresser 7-in-1 Weather Station",
    174: "EcoDHOME Smart Socket",
    175: "LaCrosse View LTV-R1/R3",
    176: "BlueLine PowerCost Monitor",
    177: "Burnhard BBQ Thermometer",
    178: "Security+ (Keyfob)",
    179: "Cavius Smoke, Heat & Water Detector",
    180: "Jansite Solar TPMS",
    181: "Amazon Basics Meat Thermometer",
    182: "TFA Marbella Pool Thermometer",
    183: "Auriol AHFL Temp/Hygro",
    184: "Auriol AFT 77 B2 Temp",
    185: "Honeywell CM921 Wireless Thermostat",
    186: "Hyundai VDO TPMS",
    187: "RojaFlex Shutter / Awning Motor",
    188: "Marlec Solar iBoost+",
    189: "Somfy io-homecontrol",
    190: "Ambient Weather WH31L Lightning",
    191: "Markisol / E-Motion / BOFU Roller",
    192: "Govee Water Leak Detector H5054",
    193: "ContiPressureCheck TPMS",
    194: "Inkbird ITH-20R Temp/Hygro",
    195: "RainPoint Soil Temp/Moisture",
    196: "Atech-WS308 Temp",
    197: "Acurite Grill Thermometer 01185M",
    198: "EnOcean ERP1",
    199: "Linear Megacode Garage/Gate",
    200: "Auriol 4-LD5661/4-LD5972/4-LD6313",
    201: "Telldus FT0385R / Cotech Weather Station",
    202: "Funkbus / Instafunk Remote",
    203: "Porsche Boxster/Cayman TPMS",
    204: "Jasco/GE Choice Alert Security",
    205: "Telldus Weather Station FT0385R",
    206: "LaCrosse TX34-IT Rain Gauge",
    207: "SmartFire Proflame 2 Remote",
    208: "AVE TPMS",
    209: "SimpliSafe Gen 3 Home Security",
    210: "Yale HSA Alarm",
    211: "Regency Ceiling Fan Remote",
    212: "Renault 0435R TPMS",
    213: "Fine Offset Electronics WS80 Weather",
    214: "EMOS E6016 Weather Station",
    215: "Altronics X7064 Temp/Hygro",
    216: "ANT and ANT+ Devices",
    217: "EMOS E6016 Rain Gauge",
    218: "Microchip HCS200/HCS300 KeeLoq (FSK)",
    219: "Fine Offset WH45 Air Quality",
    220: "Maverick XR-30 BBQ Sensor",
    221: "Fine Offset WH34 Temp Sensor",
    222: "Rubicson Pool Thermometer 48942",
    223: "Badger ORION Water Meter",
    224: "GEO minim+ Energy Monitor",
    225: "TyreGuard 400 TPMS",
    226: "Kia TPMS",
    227: "SRSmith Pool Light Remote",
    228: "Neptune R900 Flow Meter",
    229: "WEC-2103 Temp/Hygro",
    230: "Vauno EN8822C Temp/Hygro",
    231: "Govee Water Leak Detector H5054",
    232: "TFA Dostmann 14.1504.V2 BBQ",
    233: "CED7000 Shot Timer",
    234: "Watchman Sonic Advanced / Plus",
    235: "Oil Ultrasonic SMART FSK",
    236: "Gasmate BA1008 Meat Thermometer",
    237: "Flowis Flow Meter",
    238: "Wireless M-Bus Mode T (EN 13757-4)",
    239: "Revolt NC-5462 Energy Meter",
    240: "LaCrosse TX31U-IT / TFA 30.3159",
    241: "Emax W6 Weather Station",
    242: "Baldr / RainPoint Rain Gauge",
    243: "Celsia CZC1 Thermostat",
    244: "Fine Offset WS90 Weather Station",
    245: "ThermoPro TP28b Meat Thermometer",
    246: "TFA 30.3151 Weather Station",
    247: "Bresser Water Leakage",
    248: "Nissan TPMS",
    249: "Bresser Lightning Sensor",
    250: "Schou 72543 Day Rain Gauge",
    251: "Fine Offset WH55 Water Leak",
    252: "BMW Gen4-Gen5 TPMS",
    253: "Watts WFHT-RF Thermostat",
    254: "Thermor DG950 Weather Station",
    255: "Mueller Hot Rod Water Meter",
    256: "ThermoPro TP829b 4-Probe BBQ",
    257: "BMW Gen3 TPMS",
    258: "TFA Dostmann 30.3251.02 T/H",
    259: "Fine Offset WN34 Temp Sensor",
    260: "Vaillant VRT340f Thermostat",
    261: "Bresser 8-in-1 Weather Station",
    262: "Ambient Weather WH31E Temp/Hygro",
    263: "Mercedes TPMS",
    264: "Bresser Smile T/H",
    265: "Vevor 7-in-1 Weather Station",
}

RTL433_PROTOCOLS_FULL: Dict[int, str] = dict(RTL433_PROTOCOLS)
_CURATED_PROTOCOL_IDS = set(RTL433_PROTOCOLS.keys())
_protocols_loaded_from_binary = False
_rtl433_g_args: List[str] = []


def shorten_rtl433_protocol_name(raw_desc: str, max_len: int = 45) -> str:
    """Shortens long rtl_433 -R descriptions cleanly at the first comma if > max_len chars."""
    desc = str(raw_desc or "").strip()
    if len(desc) <= max_len:
        return desc
    if "," in desc:
        first_part = desc.split(",", 1)[0].strip()
        if 4 <= len(first_part) <= max_len:
            return first_part
    return desc[: max_len - 3].rstrip() + "..."


def load_rtl433_protocols_from_binary() -> int:
    """
    Runs `rtl_433 -R` once on startup to dynamically populate RTL433_PROTOCOLS
    and RTL433_PROTOCOLS_FULL, and probes `-G 4` support on the installed binary.
    """
    global _protocols_loaded_from_binary, _rtl433_g_args
    if _protocols_loaded_from_binary:
        return len(RTL433_PROTOCOLS)
    _protocols_loaded_from_binary = True

    binary = shutil.which("rtl_433") or "/usr/local/bin/rtl_433"
    try:
        proc = subprocess.run(
            [binary, "-R"],
            capture_output=True,
            text=True,
            timeout=4.0,
            check=False,
        )
        combined = f"{proc.stdout or ''}\n{proc.stderr or ''}"
        loaded_count = 0
        for raw_line in combined.splitlines():
            m = PROTOCOL_LINE_RE.match(raw_line)
            if not m:
                continue
            try:
                proto_id = int(m.group(1))
            except ValueError:
                continue
            full_desc = m.group(2).strip()
            if not full_desc:
                continue
            RTL433_PROTOCOLS_FULL[proto_id] = full_desc
            if proto_id not in _CURATED_PROTOCOL_IDS:
                RTL433_PROTOCOLS[proto_id] = shorten_rtl433_protocol_name(full_desc, 45)
            loaded_count += 1
        if loaded_count > 0:
            logger.info("Loaded %d rtl_433 protocol definitions from binary", loaded_count)
    except Exception as exc:
        logger.debug("Using built-in rtl_433 protocol catalog (%s)", exc)

    # Probe whether the installed rtl_433 binary supports `-G 4` (enable all non-test decoders)
    for candidate_args in (["-G", "4"], ["-G"]):
        try:
            probe = subprocess.run(
                [binary, *candidate_args, "-V"],
                capture_output=True,
                text=True,
                timeout=2.5,
                check=False,
            )
            if probe.returncode == 0:
                _rtl433_g_args = list(candidate_args)
                break
        except Exception:
            pass

    return len(RTL433_PROTOCOLS)


def get_rtl433_protocol_info(proto_num: Any, model: Optional[str] = None) -> Tuple[str, str]:
    """
    Returns (short_protocol_name, full_protocol_description) for a given rtl_433 protocol number.
    Falls back to `model` if the protocol number is not in RTL433_PROTOCOLS.
    """
    try:
        pid = int(str(proto_num).strip().lstrip("#"))
    except (ValueError, TypeError):
        fallback = str(model or "").strip()
        return fallback, fallback

    short_name = RTL433_PROTOCOLS.get(pid)
    full_name = RTL433_PROTOCOLS_FULL.get(pid)
    if short_name:
        return short_name, full_name or short_name

    fallback_model = str(model or "").strip()
    if fallback_model and fallback_model.lower() != "unknown":
        return fallback_model, fallback_model
    return f"rtl_433 #{pid}", f"rtl_433 Protocol #{pid}"


def get_rtl433_protocol_name(proto_num: Any, model: Optional[str] = None) -> str:
    """Returns the human-readable short name for an rtl_433 protocol number."""
    short_name, _ = get_rtl433_protocol_info(proto_num, model)
    return short_name


def is_wireless_mbus_or_meter(model: Optional[str], payload: Optional[Dict[str, Any]] = None) -> bool:
    """
    Returns True if the model or payload represents a Wireless M-Bus (EN 13757-4)
    or utility meter (water, district heating, electricity, gas).
    """
    p = payload if isinstance(payload, dict) else {}
    proto_raw = p.get("protocol")
    if proto_raw is not None:
        try:
            pid = int(str(proto_raw).strip().lstrip("#"))
            if pid in WMBUS_AND_METER_PROTOCOLS:
                return True
        except (ValueError, TypeError):
            pass

    model_lower = str(model or p.get("model") or "").strip().lower()
    if model_lower and any(w in model_lower for w in WMBUS_AND_METER_MODEL_KEYWORDS):
        if not any(c_word in model_lower for c_word in ("thermometer", "hygrometer", "barometer", "anemometer", "weather", "atc")):
            return True

    lower_keys = {str(k).lower() for k in p.keys()}
    if lower_keys & WMBUS_AND_METER_PAYLOAD_KEYS:
        return True

    return False


def enrich_wmbus_and_meter_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches Wireless M-Bus (wM-Bus) and utility meter payloads with normalized
    fields (`meter_type`, `mode`, `category`) so water, heat, and electricity meters
    are categorized under `Energy` (`Energi & Mätare`) and render clear telemetry pills.
    """
    if not isinstance(payload, dict):
        return payload

    model_str = str(payload.get("model") or "").strip()
    if not is_wireless_mbus_or_meter(model_str, payload):
        return payload

    if not payload.get("category"):
        payload["category"] = "Energy"

    # Normalize meter_type from rtl_433 wM-Bus OMS fields (`type_string`, `device_type`, `utility`)
    if not payload.get("meter_type"):
        for candidate_key in ("type_string", "device_type", "utility", "medium"):
            val = payload.get(candidate_key)
            if val is not None and str(val).strip() != "":
                payload["meter_type"] = str(val).strip()
                break

    # Normalize wM-Bus mode (T1, C1, S1, N1/N2) if protocol is Wireless M-Bus
    if not payload.get("mode"):
        proto_raw = payload.get("protocol")
        try:
            pid = int(str(proto_raw).strip().lstrip("#")) if proto_raw is not None else 0
        except (ValueError, TypeError):
            pid = 0
        if pid == 104:
            payload["mode"] = "C1/T1"
        elif pid == 105:
            payload["mode"] = "S1"
        elif pid == 106:
            payload["mode"] = "R"
        elif pid == 107:
            payload["mode"] = "F"
        elif pid == 238:
            payload["mode"] = "T1"

    return payload


def normalize_sdr_sensor_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes all remaining rtl_433 sensor telemetry fields so no measurement is ever lost:
    - Solar, Light & UV: uv / uvi / uv_index, light_lux / lux / illuminance, solar_radiation / light_wm2 / irradiance
    - Lightning (WH57, Acurite 6045M, Bresser): strike_count / storm_count / lightning_counter, storm_dist / strike_distance / lightning_distance_km
    - Soil Moisture & Tank/Pool Level (WH51, Watchman Sonic, TS-FT002): moisture / soil_moisture, depth_cm / level_cm / tank_level
    - Air Quality (WH41/WH45, etc.): co2 / co2_ppm, pm2_5_ug_m3 / pm25, pm10_0_ug_m3 / pm10, tvoc / voc
    - Security, Smoke, Water Leak & Remotes: smoke / fire / alarm, water_leak / leak / wet, motion / pir / occupancy,
      contact / door / window / opened, tamper, button / cmd / command / state
    """
    if not isinstance(payload, dict):
        return payload

    # 1. Solar / UV / Illuminance
    if payload.get("uv") is None:
        for k in ("uvi", "uv_index", "uv_idx"):
            if payload.get(k) is not None:
                payload["uv"] = payload[k]
                break

    if payload.get("lux") is None:
        for k in ("light_lux", "illuminance", "light_klx"):
            if payload.get(k) is not None:
                try:
                    val = float(payload[k])
                    if k == "light_klx":
                        val = val * 1000.0
                    payload["lux"] = round(val, 1)
                except (ValueError, TypeError):
                    payload["lux"] = payload[k]
                break

    if payload.get("solar_radiation") is None:
        for k in ("light_wm2", "irradiance", "solar_wm2", "uv_wm2"):
            if payload.get(k) is not None:
                payload["solar_radiation"] = payload[k]
                break

    # 2. Lightning / Storm detectors
    if payload.get("strike_count") is None:
        for k in ("storm_count", "lightning_counter", "strikes", "strike_cnt"):
            if payload.get(k) is not None:
                payload["strike_count"] = payload[k]
                break

    if payload.get("storm_dist") is None:
        for k in ("strike_distance", "lightning_distance_km", "storm_dist_km", "distance_km"):
            if payload.get(k) is not None:
                payload["storm_dist"] = payload[k]
                break

    # 3. Soil Moisture & Liquid/Tank Level
    if payload.get("moisture") is None and payload.get("soil_moisture") is not None:
        payload["moisture"] = payload["soil_moisture"]

    if payload.get("depth_cm") is None:
        for k in ("level_cm", "tank_level", "water_depth_cm", "liquid_level_cm"):
            if payload.get(k) is not None:
                payload["depth_cm"] = payload[k]
                break
        if payload.get("depth_cm") is None and payload.get("depth_m") is not None:
            try:
                payload["depth_cm"] = round(float(payload["depth_m"]) * 100.0, 1)
            except (ValueError, TypeError):
                pass

    # 4. Air Quality (CO2, PM2.5, PM10, VOC)
    if payload.get("co2") is None and payload.get("co2_ppm") is not None:
        payload["co2"] = payload["co2_ppm"]

    if payload.get("pm2_5_ug_m3") is None and payload.get("pm25") is not None:
        payload["pm2_5_ug_m3"] = payload["pm25"]
    if payload.get("pm10_0_ug_m3") is None and payload.get("pm10") is not None:
        payload["pm10_0_ug_m3"] = payload["pm10"]

    return payload


def compute_payload_signature(payload: Dict[str, Any]) -> str:
    filtered = {k: v for k, v in payload.items() if k not in VOLATILE_KEYS}
    canonical = json.dumps(filtered, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()


def parse_duration_to_seconds(raw: Any, default_sec: int = 60) -> int:
    """
    Parses a duration string into integer seconds (minimum 5s).
    Supports:
    - 'HH:MM:SS' (e.g. '00:05:00' -> 300, '00:01:00' -> 60)
    - 'MM:SS' (e.g. '05:00' -> 300, '01:00' -> 60)
    - '5m', '1h30m', '90s'
    - Plain integer/float seconds (e.g. '60', '300')
    """
    s = str(raw if raw is not None else "").strip()
    if not s:
        return max(5, default_sec)

    if ":" in s:
        parts = [p.strip() for p in s.split(":")]
        try:
            if len(parts) == 3:
                h, m, sec = int(parts[0] or 0), int(parts[1] or 0), float(parts[2] or 0)
                total = int(round(h * 3600 + m * 60 + sec))
                return max(5, total)
            if len(parts) == 2:
                m, sec = int(parts[0] or 0), float(parts[1] or 0)
                total = int(round(m * 60 + sec))
                return max(5, total)
        except (ValueError, TypeError):
            return max(5, default_sec)

    unit_matches = re.findall(r"(\d+(?:\.\d+)?)\s*([hmsHMS])", s)
    if unit_matches:
        total_f = 0.0
        for val_str, unit_ch in unit_matches:
            v = float(val_str)
            u = unit_ch.lower()
            if u == "h":
                total_f += v * 3600.0
            elif u == "m":
                total_f += v * 60.0
            else:
                total_f += v
        return max(5, int(round(total_f)))

    try:
        return max(5, int(round(float(s))))
    except (ValueError, TypeError):
        return max(5, default_sec)


def format_seconds_to_hhmmss(seconds: Any) -> str:
    sec = parse_duration_to_seconds(seconds, 60)
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


class RTLManager:
    def __init__(
        self,
        get_settings_fn: Callable[[], Dict[str, str]],
        on_signal_fn: Callable[[Dict[str, Any]], Awaitable[None]],
        on_status_change_fn: Callable[[Dict[str, Any]], Awaitable[None]],
        on_stderr_line_fn: Callable[[str], Awaitable[None]],
        on_freq_change_fn: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
    ):
        self._get_settings = get_settings_fn
        self._on_signal = on_signal_fn
        self._on_status_change = on_status_change_fn
        self._on_stderr_line = on_stderr_line_fn
        self._on_freq_change = on_freq_change_fn

        self._process: Optional[asyncio.subprocess.Process] = None
        self._watchdog_task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._restart_event = asyncio.Event()
        self._process_lock = asyncio.Lock()

        self._state: str = "stopped"
        self._current_cmd: List[str] = []
        self._started_at: Optional[float] = None
        self._last_error: str = ""
        self._stderr_buffer: Deque[str] = collections.deque(maxlen=200)
        self._debounce_cache: Dict[str, Tuple[str, float]] = {}
        self._debounced_count: int = 0
        self._received_count: int = 0
        self._restart_count: int = 0
        self._disable_g_flag: bool = False

        self._current_tuned_freq: str = "433.92 MHz"
        self._last_hop_timestamp: float = time.time()
        self.hop_start_monotonic: float = time.monotonic()
        self._hop_interval: int = 60
        self.hop_interval: int = 60
        self.hop_intervals: List[int] = [60, 60]
        self._active_freqs: List[str] = ["433.92 MHz", WIDEBAND_868_DISPLAY]
        self.hop_freqs: List[str] = ["433.92 MHz", WIDEBAND_868_DISPLAY]
        self._last_hop_index: int = 0

    def reset_stats_and_cache(self) -> None:
        self._debounce_cache.clear()
        self._debounced_count = 0
        self._received_count = 0

    def evict_device(self, model: str, device_id: str) -> None:
        self._debounce_cache.pop(f"{model}:{device_id}", None)

    def _resolve_sample_rate(self, settings: Dict[str, str]) -> str:
        raw_sr = str(settings.get("custom_sample_rate", DEFAULT_SAMPLE_RATE)).strip()
        if not raw_sr:
            return DEFAULT_SAMPLE_RATE
        sr_low = raw_sr.lower()
        if sr_low in ("2048k", "2.048m", "2048000", "2m"):
            return "2048k"
        if sr_low in ("1024k", "1.024m", "1024000", "1m"):
            return "1024k"
        return raw_sr

    def _resolve_868_band(self, settings: Dict[str, str]) -> Tuple[str, str]:
        sr = self._resolve_sample_rate(settings)
        if sr == "2048k":
            return WIDEBAND_868_2048K_RTL_FREQ, WIDEBAND_868_2048K_DISPLAY
        return WIDEBAND_868_RTL_FREQ, WIDEBAND_868_DISPLAY

    def _resolve_hop_schedule(self, settings: Dict[str, str]) -> Tuple[List[str], List[str], List[int]]:
        """
        Resolves (raw_rtl_freqs, display_freqs, hop_intervals_seconds) from settings.
        - With -s 2048k: 868 band is centered on 868.90M (covers 867.88 - 869.92 MHz: 868.30 + 868.95 + 869.525 MHz in 1 sweep).
        - With -s 1024k: 868 band is centered on 868.60M (868.08 - 869.12 MHz), and in '868' mode sweeps 868.60M + 869.525M.
        - Supports '433', '868', 'hop' (Dual Hop), 'hop_eu' (Triple Hop EU + 169.44 MHz wM-Bus), 'hop_global' (Quad Hop Global 315/433/868/915), and 'custom'.
        """
        mode = str(settings.get("mode", "hop")).strip().lower()
        base_default_sec = parse_duration_to_seconds(settings.get("hop_interval", "60"), 60)
        sec_433 = parse_duration_to_seconds(settings.get("hop_time_433") or base_default_sec, base_default_sec)
        sec_868 = parse_duration_to_seconds(settings.get("hop_time_868") or base_default_sec, base_default_sec)
        sr = self._resolve_sample_rate(settings)
        freq_868, disp_868 = self._resolve_868_band(settings)

        if mode == "433":
            return ["433.92M"], ["433.92 MHz"], [sec_433]
        if mode == "868":
            if sr == "2048k":
                return [WIDEBAND_868_2048K_RTL_FREQ], [WIDEBAND_868_2048K_DISPLAY], [sec_868]
            return [WIDEBAND_868_RTL_FREQ, "869.525M"], [WIDEBAND_868_DISPLAY, "869.52 MHz"], [sec_868, max(15, sec_868 // 2)]
        if mode in ("hop_eu", "triple_eu"):
            return (
                ["433.92M", freq_868, VHF_WMBUS_169_RTL_FREQ],
                ["433.92 MHz", disp_868, VHF_WMBUS_169_DISPLAY],
                [sec_433, sec_868, base_default_sec],
            )
        if mode in ("hop_global", "quad_global"):
            return (
                ["315.00M", "433.92M", freq_868, "915.00M"],
                ["315.00 MHz", "433.92 MHz", disp_868, "915.00 MHz"],
                [base_default_sec, sec_433, sec_868, base_default_sec],
            )
        if mode == "custom":
            raw_freqs = str(settings.get("custom_freqs", f"433.92M,{freq_868}"))
            raw_items = [f.strip() for f in raw_freqs.replace(";", ",").split(",") if f.strip()]
            if not raw_items:
                raw_items = ["433.92M"]

            raw_hop_str = str(settings.get("hop_interval", "60"))
            hop_tokens = [
                parse_duration_to_seconds(t.strip(), base_default_sec)
                for t in raw_hop_str.replace(";", ",").split(",")
                if t.strip()
            ] or [base_default_sec]

            rtl_freqs: List[str] = []
            disp_freqs: List[str] = []
            intervals: List[int] = []

            for idx, item in enumerate(raw_items):
                inline_dur: Optional[int] = None
                freq_part = item
                if "@" in item:
                    freq_part, dur_part = item.split("@", 1)
                    freq_part = freq_part.strip()
                    inline_dur = parse_duration_to_seconds(dur_part.strip(), base_default_sec)

                rtl_freqs.append(freq_part)
                m = re.match(r"^([0-9.]+)\s*[mM]?(?:[hH][zZ])?$", freq_part)
                disp_f = freq_part
                if m:
                    try:
                        val = float(m.group(1))
                        if val > 1_000_000:
                            val = val / 1_000_000.0
                        if abs(val - 868.90) < 0.05:
                            disp_f = WIDEBAND_868_2048K_DISPLAY
                        elif abs(val - 868.60) < 0.05 or abs(val - 868.50) < 0.05:
                            disp_f = WIDEBAND_868_DISPLAY
                        elif abs(val - 169.4375) < 0.05 or abs(val - 169.44) < 0.05:
                            disp_f = VHF_WMBUS_169_DISPLAY
                        else:
                            disp_f = f"{val:.2f} MHz"
                    except ValueError:
                        pass
                disp_freqs.append(disp_f)

                if inline_dur is not None:
                    intervals.append(inline_dur)
                elif len(hop_tokens) > 1 and idx < len(hop_tokens):
                    intervals.append(hop_tokens[idx])
                elif "433" in disp_f and settings.get("hop_time_433"):
                    intervals.append(sec_433)
                elif "868" in disp_f and settings.get("hop_time_868"):
                    intervals.append(sec_868)
                else:
                    intervals.append(hop_tokens[-1])

            return rtl_freqs, disp_freqs, intervals

        # Default: Dual Hop (433.92 MHz + Wideband 868/869 MHz)
        return ["433.92M", freq_868], ["433.92 MHz", disp_868], [sec_433, sec_868]

    def _resolve_active_freqs(self, settings: Dict[str, str]) -> List[str]:
        _, disp_freqs, _ = self._resolve_hop_schedule(settings)
        return disp_freqs

    def _compute_hop_state(self) -> Tuple[str, int, int, int]:
        freqs = self.hop_freqs or self._active_freqs or ["433.92 MHz"]
        intervals = (
            self.hop_intervals
            if len(self.hop_intervals) == len(freqs)
            else [max(5, int(self._hop_interval or 60))] * len(freqs)
        )
        if len(freqs) <= 1 or self._state != "running":
            dur0 = intervals[0] if intervals else max(5, int(self._hop_interval or 60))
            return freqs[0], dur0, 0, dur0

        total_cycle = max(5, sum(max(5, iv) for iv in intervals))
        elapsed = max(0.0, time.monotonic() - self.hop_start_monotonic)
        cycle_pos = elapsed % total_cycle

        acc = 0.0
        for idx, f_name in enumerate(freqs):
            band_dur = max(5, int(intervals[idx]))
            if cycle_pos < acc + band_dur or idx == len(freqs) - 1:
                pos_in_band = max(0.0, cycle_pos - acc)
                remaining_sec = max(1, int(band_dur - pos_in_band))
                return f_name, remaining_sec, idx, band_dur
            acc += band_dur

        return freqs[0], intervals[0], 0, intervals[0]

    def get_freq_state(self) -> Dict[str, Any]:
        settings = self._get_settings()
        current_freq, remaining_sec, _, band_dur = self._compute_hop_state()
        self._current_tuned_freq = current_freq
        return {
            "mode": settings.get("mode", "hop"),
            "freq": current_freq,
            "current_tuned_freq": current_freq,
            "remaining": remaining_sec,
            "last_hop_timestamp": time.time() - (band_dur - remaining_sec),
            "hop_interval": band_dur,
            "hop_intervals": self.hop_intervals,
            "hop_time_433": format_seconds_to_hhmmss(settings.get("hop_time_433") or settings.get("hop_interval", "60")),
            "hop_time_868": format_seconds_to_hhmmss(settings.get("hop_time_868") or settings.get("hop_interval", "60")),
            "active_freqs": self._active_freqs,
        }

    async def _emit_freq_change(self) -> None:
        if self._on_freq_change is not None:
            try:
                await self._on_freq_change(self.get_freq_state())
            except Exception as exc:
                logger.debug("Error in on_freq_change callback: %s", exc)

    async def _check_and_handle_tuned_line(self, line: str) -> bool:
        m = TUNED_TO_RE.search(line)
        if not m:
            return False
        try:
            freq_val = float(m.group(1))
            if freq_val > 1_000_000:
                freq_val = freq_val / 1_000_000.0
            new_freq = f"{freq_val:.2f} MHz"

            matched_idx: Optional[int] = None
            if new_freq in self.hop_freqs:
                matched_idx = self.hop_freqs.index(new_freq)
            elif 869.3 <= freq_val <= 870.5 and any("869.52" in hf for hf in self.hop_freqs):
                for i, hf in enumerate(self.hop_freqs):
                    if "869.52" in hf and "868.30" not in hf:
                        matched_idx = i
                        new_freq = hf
                        break
            elif 860.0 <= freq_val <= 875.0:
                for i, hf in enumerate(self.hop_freqs):
                    if "868" in hf or "869" in hf:
                        matched_idx = i
                        new_freq = hf
                        break
            elif 430.0 <= freq_val <= 440.0:
                for i, hf in enumerate(self.hop_freqs):
                    if "433" in hf:
                        matched_idx = i
                        new_freq = hf
                        break
            elif 168.0 <= freq_val <= 171.0:
                for i, hf in enumerate(self.hop_freqs):
                    if "169" in hf:
                        matched_idx = i
                        new_freq = hf
                        break
            elif 310.0 <= freq_val <= 320.0:
                for i, hf in enumerate(self.hop_freqs):
                    if "315" in hf:
                        matched_idx = i
                        new_freq = hf
                        break
            elif 902.0 <= freq_val <= 928.0:
                for i, hf in enumerate(self.hop_freqs):
                    if "915" in hf:
                        matched_idx = i
                        new_freq = hf
                        break

            if matched_idx is not None and len(self.hop_freqs) > 1:
                offset_before = sum(max(5, int(x)) for x in self.hop_intervals[:matched_idx])
                self.hop_start_monotonic = time.monotonic() - offset_before
                self._last_hop_index = matched_idx

            self._current_tuned_freq = new_freq
            self._last_hop_timestamp = time.time()
            await self._emit_freq_change()
            return True
        except ValueError:
            return False

    def build_command(self, settings: Dict[str, str]) -> List[str]:
        binary = shutil.which("rtl_433") or "/usr/local/bin/rtl_433"
        device_index = str(settings.get("device_index", "0")).strip() or "0"
        raw_gain = str(settings.get("gain", "auto")).strip().replace(",", ".")
        gain = re.sub(r"\s*db$", "", raw_gain, flags=re.IGNORECASE).strip() or "auto"
        ppm = str(settings.get("ppm", "0")).strip().replace(",", ".")
        rtl_freqs, _, intervals = self._resolve_hop_schedule(settings)
        sample_rate = self._resolve_sample_rate(settings)

        cmd: List[str] = [
            binary,
            "-d",
            device_index,
            "-C",
            "si",
            "-F",
            "json",
            "-F",
            "log",
            "-M",
            "time:iso",
            "-M",
            "level",
            "-M",
            "protocol",
        ]

        # Enable all non-test decoders (including Wireless M-Bus #104/#105/#238) if supported by binary
        if _rtl433_g_args and not self._disable_g_flag:
            cmd.extend(_rtl433_g_args)

        for f in rtl_freqs:
            cmd.extend(["-f", f])

        if len(rtl_freqs) > 1:
            if len(set(intervals)) == 1:
                cmd.extend(["-H", str(intervals[0])])
            else:
                for iv in intervals:
                    cmd.extend(["-H", str(iv)])

        cmd.extend(["-s", sample_rate])

        if gain and gain.lower() != "auto":
            cmd.extend(["-g", gain])

        if ppm and ppm not in ("0", "0.0", ""):
            cmd.extend(["-p", ppm])

        return cmd

    def get_status(self) -> Dict[str, Any]:
        settings = self._get_settings()
        uptime_sec = 0
        if self._state == "running" and self._started_at is not None:
            uptime_sec = max(0, int(time.time() - self._started_at))

        current_freq, remaining_sec, _, band_dur = self._compute_hop_state()
        self._current_tuned_freq = current_freq

        return {
            "running": self._state == "running",
            "state": self._state,
            "pid": self._process.pid if self._process and self._process.returncode is None else None,
            "mode": settings.get("mode", "hop"),
            "device_index": settings.get("device_index", "0"),
            "gain": settings.get("gain", "auto"),
            "ppm": settings.get("ppm", "0"),
            "hop_interval": band_dur,
            "hop_intervals": self.hop_intervals,
            "hop_time_433": format_seconds_to_hhmmss(settings.get("hop_time_433") or settings.get("hop_interval", "60")),
            "hop_time_868": format_seconds_to_hhmmss(settings.get("hop_time_868") or settings.get("hop_interval", "60")),
            "freq": current_freq,
            "current_tuned_freq": current_freq,
            "remaining": remaining_sec,
            "last_hop_timestamp": time.time() - (band_dur - remaining_sec),
            "active_freqs": self._active_freqs,
            "custom_freqs": settings.get("custom_freqs", f"433.92M,{WIDEBAND_868_RTL_FREQ}"),
            "custom_sample_rate": settings.get("custom_sample_rate", DEFAULT_SAMPLE_RATE),
            "debounce_seconds": float(settings.get("debounce_seconds", "2.0") or 2.0),
            "command": " ".join(self.build_command(settings)),
            "uptime_seconds": uptime_sec,
            "last_error": self._last_error,
            "stderr_tail": list(self._stderr_buffer)[-40:],
            "received_count": self._received_count,
            "debounced_count": self._debounced_count,
            "restart_count": self._restart_count,
        }

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        try:
            await asyncio.to_thread(load_rtl433_protocols_from_binary)
        except Exception:
            pass
        self._watchdog_task = asyncio.create_task(self._watchdog_loop(), name="rtl_433_watchdog")

    async def stop(self) -> None:
        self._running = False
        self._restart_event.set()
        await self._terminate_process()
        if self._watchdog_task is not None:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
            self._watchdog_task = None
        self._state = "stopped"
        await self._on_status_change(self.get_status())

    async def restart(self) -> None:
        logger.info("Restarting rtl_433 subprocess on user/config request...")
        self._current_cmd = self.build_command(self._get_settings())
        self._restart_event.set()
        await self._terminate_process()
        await asyncio.sleep(0.05)

    async def _terminate_process(self) -> None:
        async with self._process_lock:
            proc = self._process
            if proc is not None and proc.returncode is None:
                try:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=3.0)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    logger.debug("Error terminating rtl_433: %s", exc)
            self._process = None

    def append_raw_log(self, formatted_line: str) -> str:
        self._stderr_buffer.append(formatted_line)
        return formatted_line

    def _append_stderr(self, line: str) -> str:
        if re.match(r"^\d{2}:\d{2}:\d{2}\s+\|\s+\[", line):
            self._stderr_buffer.append(line)
            return line
        ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        formatted = f"{ts} | [{'SDR':<6}] | {'RTL-SDR V4':<11} | {line}"
        self._stderr_buffer.append(formatted)
        return formatted

    def _is_debounced(self, payload: Dict[str, Any], debounce_window: float) -> bool:
        if debounce_window <= 0:
            return False

        now = time.monotonic()
        if len(self._debounce_cache) > 1000:
            expired = [k for k, (_, ts) in self._debounce_cache.items() if now - ts > max(debounce_window * 2, 30.0)]
            for k in expired:
                self._debounce_cache.pop(k, None)

        model = str(payload.get("model") or "Unknown").strip()
        dev_id = extract_device_id(payload)
        dev_key = f"{model}:{dev_id}"
        sig = compute_payload_signature(payload)

        prev = self._debounce_cache.get(dev_key)
        if prev is not None:
            prev_sig, prev_ts = prev
            if prev_sig == sig and (now - prev_ts) < debounce_window:
                self._debounced_count += 1
                return True

        self._debounce_cache[dev_key] = (sig, now)
        return False

    async def _read_stdout(self, stream: asyncio.StreamReader) -> None:
        while True:
            line_bytes = await stream.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            if not line.startswith("{"):
                await self._check_and_handle_tuned_line(line)
                continue

            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    continue
            except json.JSONDecodeError:
                continue

            proto_raw = payload.get("protocol")
            if proto_raw is not None and str(proto_raw).strip() != "":
                p_short, p_full = get_rtl433_protocol_info(proto_raw, payload.get("model"))
                if p_short:
                    payload["protocol_name"] = p_short
                if p_full and p_full != p_short:
                    payload["protocol_full_name"] = p_full

            # Enrich Wireless M-Bus (#104/#105/#238) and utility meters with normalized fields & Energy category
            enrich_wmbus_and_meter_payload(payload)
            normalize_sdr_sensor_payload(payload)

            # Only infer frequency from packet in fixed single-frequency mode
            if len(self.hop_freqs) <= 1:
                pkt_freq = extract_freq_mhz(payload)
                if pkt_freq is not None:
                    inferred_band = None
                    if 430.0 <= pkt_freq <= 440.0:
                        inferred_band = "433.92 MHz"
                    elif 860.0 <= pkt_freq <= 875.0:
                        inferred_band = WIDEBAND_868_DISPLAY
                    else:
                        inferred_band = f"{pkt_freq:.2f} MHz"

                    if inferred_band and inferred_band != self._current_tuned_freq:
                        self._current_tuned_freq = inferred_band
                        self._last_hop_timestamp = time.time()
                        await self._emit_freq_change()

            settings = self._get_settings()
            try:
                debounce_sec = float(settings.get("debounce_seconds", "2.0"))
            except (ValueError, TypeError):
                debounce_sec = 2.0

            if self._is_debounced(payload, debounce_sec):
                continue

            self._received_count += 1
            try:
                await self._on_signal(payload)
            except Exception as exc:
                logger.error("Error processing signal callback: %s", exc)

    async def _read_stderr(self, stream: asyncio.StreamReader) -> None:
        while True:
            line_bytes = await stream.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            await self._check_and_handle_tuned_line(line)

            formatted = self._append_stderr(line)
            lower = line.lower()
            if any(
                err_tok in lower
                for err_tok in (
                    "usb_open error",
                    "no supported devices found",
                    "failed to open rtlsdr device",
                    "usb_claim_interface error",
                    "kernel driver is active",
                    "rtlsdr_read_async failed",
                    "LIBUSB_ERROR",
                    "libusb_error",
                    "no matching device",
                )
            ):
                self._last_error = line

            try:
                await self._on_stderr_line(formatted)
            except Exception:
                pass

    async def _hop_tracker_loop(self) -> None:
        while self._state == "running" and self._process and self._process.returncode is None:
            await asyncio.sleep(0.25)
            if len(self.hop_freqs) <= 1:
                continue
            current_freq, _, hop_index, band_dur = self._compute_hop_state()
            if hop_index != self._last_hop_index or current_freq != self._current_tuned_freq:
                self._last_hop_index = hop_index
                self._current_tuned_freq = current_freq
                self._hop_interval = band_dur
                self.hop_interval = band_dur
                self._last_hop_timestamp = time.time()
                ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
                short_freq_col = "868.60 MHz" if "868" in current_freq and len(current_freq) > 11 else current_freq[:11]
                freq_col = f"{short_freq_col:<11}"
                name_col = f"{f'Frekvenshopp -> {current_freq}':<42}"
                meas_col = f"{f'Lyssnar i {format_seconds_to_hhmmss(band_dur)} ({band_dur}s)':<32}"
                hop_line = self.append_raw_log(
                    f"{ts} | [{'SDR':<6}] | {freq_col} | {name_col} | {meas_col} | RSSI: {'-':>5}    "
                )
                try:
                    await self._on_stderr_line(hop_line)
                except Exception:
                    pass
                await self._emit_freq_change()

    async def _watchdog_loop(self) -> None:
        while self._running:
            self._restart_event.clear()
            settings = self._get_settings()
            cmd = self.build_command(settings)
            self._current_cmd = cmd
            _, disp_freqs, intervals = self._resolve_hop_schedule(settings)
            self._active_freqs = disp_freqs
            self.hop_freqs = list(disp_freqs)
            self.hop_intervals = list(intervals) if intervals else [60]
            self._hop_interval = self.hop_intervals[0]
            self.hop_interval = self._hop_interval
            self._current_tuned_freq = self.hop_freqs[0]
            self.hop_start_monotonic = time.monotonic()
            self._last_hop_index = 0
            self._last_hop_timestamp = time.time()

            self._state = "starting"
            await self._on_status_change(self.get_status())

            try:
                logger.info("Starting rtl_433: %s", " ".join(cmd))
                start_line = self._append_stderr(f"Startar: {' '.join(cmd)}")
                await self._on_stderr_line(start_line)

                proc_start_mono = time.monotonic()
                async with self._process_lock:
                    self._process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

                self._started_at = time.time()
                self.hop_start_monotonic = time.monotonic()
                self._last_hop_index = 0
                self._last_hop_timestamp = self._started_at
                self._state = "running"
                self._last_error = ""
                await self._on_status_change(self.get_status())
                await self._emit_freq_change()

                stdout_task = asyncio.create_task(self._read_stdout(self._process.stdout))
                stderr_task = asyncio.create_task(self._read_stderr(self._process.stderr))
                hop_task = asyncio.create_task(self._hop_tracker_loop())

                return_code = await self._process.wait()
                hop_task.cancel()
                await asyncio.gather(stdout_task, stderr_task, hop_task, return_exceptions=True)

                if not self._running:
                    break

                # Automatic fallback if -G flag caused immediate exit on an older rtl_433 binary
                if (
                    return_code != 0
                    and "-G" in cmd
                    and not self._disable_g_flag
                    and (time.monotonic() - proc_start_mono) < 3.0
                ):
                    self._disable_g_flag = True
                    fallback_line = self._append_stderr(
                        "Flaggan -G stöds ej av denna rtl_433-version, startar om med standardprotokoll..."
                    )
                    await self._on_stderr_line(fallback_line)
                    continue

                if self._restart_event.is_set():
                    self._restart_count += 1
                    restart_line = self._append_stderr("Omstart begärd, laddar nya inställningar...")
                    await self._on_stderr_line(restart_line)
                    continue

                self._state = "error"
                self._started_at = None
                self._restart_count += 1
                if not self._last_error:
                    self._last_error = f"rtl_433 avslutades oväntat (exit code {return_code})"
                stop_line = self._append_stderr(f"Processen stoppade (kod {return_code}). Försöker igen om 5 sekunder...")
                await self._on_stderr_line(stop_line)
                await self._on_status_change(self.get_status())

            except FileNotFoundError:
                self._state = "error"
                self._started_at = None
                self._last_error = "Kunde inte hitta binären 'rtl_433'. Kontrollera att containern är korrekt byggd."
                formatted = self._append_stderr(self._last_error)
                await self._on_stderr_line(formatted)
                await self._on_status_change(self.get_status())
            except Exception as exc:
                self._state = "error"
                self._started_at = None
                self._last_error = f"Fel vid start av rtl_433: {exc}"
                formatted = self._append_stderr(self._last_error)
                await self._on_stderr_line(formatted)
                await self._on_status_change(self.get_status())

            if not self._running:
                break

            try:
                await asyncio.wait_for(self._restart_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass


SDRManager = RTLManager

__all__ = [
    "DEFAULT_SAMPLE_RATE",
    "RTL433_PROTOCOLS",
    "RTL433_PROTOCOLS_FULL",
    "RTLManager",
    "SDRManager",
    "VALID_SDR_MODES",
    "VHF_WMBUS_169_DISPLAY",
    "VHF_WMBUS_169_RTL_FREQ",
    "VOLATILE_KEYS",
    "WIDEBAND_868_2048K_DISPLAY",
    "WIDEBAND_868_2048K_RTL_FREQ",
    "WIDEBAND_868_DISPLAY",
    "WIDEBAND_868_RTL_FREQ",
    "WMBUS_AND_METER_MODEL_KEYWORDS",
    "WMBUS_AND_METER_PAYLOAD_KEYS",
    "WMBUS_AND_METER_PROTOCOLS",
    "compute_payload_signature",
    "enrich_wmbus_and_meter_payload",
    "format_seconds_to_hhmmss",
    "get_rtl433_protocol_info",
    "get_rtl433_protocol_name",
    "is_wireless_mbus_or_meter",
    "load_rtl433_protocols_from_binary",
    "normalize_sdr_sensor_payload",
    "parse_duration_to_seconds",
    "shorten_rtl433_protocol_name",
]
