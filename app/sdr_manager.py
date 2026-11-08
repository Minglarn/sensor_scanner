"""SDR / rtl_433 Subprocess, Dual-Hop Frequency & Protocol Lookup Manager."""

import logging
import re
import shutil
import subprocess
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("sensor_scanner.sdr")

PROTOCOL_LINE_RE = re.compile(r"^\s*\[(\d+)\]\*?\s+(.+)$")

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
    104: "Wireless M-Bus Mode C&T",
    105: "Wireless M-Bus Mode S",
    106: "Wireless M-Bus Mode R",
    107: "Wireless M-Bus Mode F",
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
    238: "Wireless M-Bus Mode T",
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
    and RTL433_PROTOCOLS_FULL with all protocols supported by the installed binary.
    """
    global _protocols_loaded_from_binary
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


from app.rtl_manager import RTLManager, compute_payload_signature  # noqa: E402

SDRManager = RTLManager

__all__ = [
    "RTL433_PROTOCOLS",
    "RTL433_PROTOCOLS_FULL",
    "RTLManager",
    "SDRManager",
    "compute_payload_signature",
    "get_rtl433_protocol_info",
    "get_rtl433_protocol_name",
    "load_rtl433_protocols_from_binary",
    "shorten_rtl433_protocol_name",
]
