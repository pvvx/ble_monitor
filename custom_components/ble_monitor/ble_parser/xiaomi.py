# Parser for Xiaomi MiBeacon BLE advertisements
import logging
import math
import struct
from Cryptodome.Cipher import AES
import random

_LOGGER = logging.getLogger(__name__)

# Sensors type dictionary
# {device type code: (device name, binary?)}
XIAOMI_TYPE_DICT = {
    0x01AA: ("LYWSDCGQ", False),
    0x0347: ("CGG1", False),
    0x0B48: ("CGG1-ENCRYPTED", False),
    0x066F: ("CGDK2", False),
    0x045B: ("LYWSD02", False),
    0x055B: ("LYWSD03MMC", False),
    0x0576: ("CGD1", False),
    0x06d3: ("MHO-C303", False),
    0x0387: ("MHO-C401", False),
    0x02DF: ("JQJCY01YM", False),
    0x0098: ("HHCCJCY01", False),
    0x03BC: ("GCLS002", False),
    0x015D: ("HHCCPOT002", False),
    0x040A: ("WX08ZM", True),
    0x098B: ("MCCGQ02HL", True),
    0x03D6: ("CGH1", True),
    0x0083: ("YM-K1501", True),
    0x0113: ("YM-K1501EU", True),
    0x045C: ("V-SK152", True),
    0x0863: ("SJWS01LM", True),
    0x07F6: ("MJYD02YL", True),
    0x03DD: ("MUE4094RT", True),
    0x0A8D: ("RTCGQ02LM", True),
    0x0A83: ("CGPR1", True),
    0x00DB: ("MMC-T201-1", False),
    0x07BF: ("YLAI003", False),
    0x0489: ("M1S-T500", False),
}

# Structured objects for data conversions
TH_STRUCT = struct.Struct("<hH")
H_STRUCT = struct.Struct("<H")
T_STRUCT = struct.Struct("<h")
TTB_STRUCT = struct.Struct("<hhB")
CND_STRUCT = struct.Struct("<H")
ILL_STRUCT = struct.Struct("<I")
LIGHT_STRUCT = struct.Struct("<I")
FMDH_STRUCT = struct.Struct("<H")
M_STRUCT = struct.Struct("<L")
P_STRUCT = struct.Struct("<H")


# Advertisement conversion of measurement data
# https://iot.mi.com/new/doc/embedded-development/ble/object-definition
def obj0300(xobj):
    return {"motion": xobj[0], "motion timer": xobj[0]}


def obj1000(xobj):
    return {"toothbrush mode": xobj[1]}


def obj0f00(xobj):
    if len(xobj) == 3:
        (value,) = LIGHT_STRUCT.unpack(xobj + b'\x00')
        # MJYD02YL:  1 - moving no light, 100 - moving with light
        # RTCGQ02LM: 0 - moving no light, 256 - moving with light
        # CGPR1:     moving, value is illumination in lux
        return {"motion": 1, "motion timer": 1, "light": int(value >= 100), "illuminance": value}
    else:
        return {}


def obj0110(xobj):
    if xobj[2] == 0:
        press = "single press"
    elif xobj[2] == 1:
        press = "double press"
    elif xobj[2] == 2:
        press = "long press"
    else:
        press = "no press"
    return {"button": press}


def obj0410(xobj):
    if len(xobj) == 2:
        (temp,) = T_STRUCT.unpack(xobj)
        return {"temperature": temp / 10}
    else:
        return {}


def obj0510(xobj):
    return {"switch": xobj[0], "temperature": xobj[1]}


def obj0610(xobj):
    if len(xobj) == 2:
        (humi,) = H_STRUCT.unpack(xobj)
        return {"humidity": humi / 10}
    else:
        return {}


def obj0710(xobj):
    if len(xobj) == 3:
        (illum,) = ILL_STRUCT.unpack(xobj + b'\x00')
        return {"illuminance": illum, "light": 1 if illum == 100 else 0}
    else:
        return {}


def obj0810(xobj):
    return {"moisture": xobj[0]}


def obj0910(xobj):
    if len(xobj) == 2:
        (cond,) = CND_STRUCT.unpack(xobj)
        return {"conductivity": cond}
    else:
        return {}


def obj1010(xobj):
    if len(xobj) == 2:
        (fmdh,) = FMDH_STRUCT.unpack(xobj)
        return {"formaldehyde": fmdh / 100}
    else:
        return {}


def obj1210(xobj):
    return {"switch": xobj[0]}


def obj1310(xobj):
    return {"consumable": xobj[0]}


def obj1410(xobj):
    return {"moisture": xobj[0]}


def obj1710(xobj):
    if len(xobj) == 4:
        (motion,) = M_STRUCT.unpack(xobj)
        # seconds since last motion detected message (not used, we use motion timer in obj0f00)
        # 0 = motion detected
        return {"motion": 1 if motion == 0 else 0}
    else:
        return {}


def obj1810(xobj):
    return {"light": xobj[0]}


def obj1910(xobj):
    return {"opening": xobj[0]}


def obj0a10(xobj):
    batt = xobj[0]
    if batt > 100:
        batt = 100
    volt = 2.2 + (3.1 - 2.2) * (batt / 100)
    return {"battery": batt, "voltage": volt}


def obj0d10(xobj):
    if len(xobj) == 4:
        (temp, humi) = TH_STRUCT.unpack(xobj)
        return {"temperature": temp / 10, "humidity": humi / 10}
    else:
        return {}


def obj0020(xobj):
    if len(xobj) == 5:
        (temp1, temp2, bat) = TTB_STRUCT.unpack(xobj)
        # Body temperature is calculated from the two measured temperatures.
        # Formula is based on approximation based on values inthe app in the range 36.5 - 37.8.
        body_temp = (
            3.71934 * pow(10, -11) * math.exp(0.69314 * temp1 / 100)
            - 1.02801 * pow(10, -8) * math.exp(0.53871 * temp2 / 100)
            + 36.413
        )
        return {"temperature": body_temp, "battery": bat}
    else:
        return {}


# Dataobject dictionary
# {dataObject_id: (converter, binary, measuring)
xiaomi_dataobject_dict = {
    0x0003: (obj0300, True, False),
    0x0010: (obj1000, False, True),
    0x000F: (obj0f00, True, True),
    0x1001: (obj0110, False, True),
    0x1004: (obj0410, False, True),
    0x1005: (obj0510, True, True),
    0x1006: (obj0610, False, True),
    0x1007: (obj0710, True, True),
    0x1008: (obj0810, False, True),
    0x1009: (obj0910, False, True),
    0x1010: (obj1010, False, True),
    0x1012: (obj1210, True, False),
    0x1013: (obj1310, False, True),
    0x1014: (obj1410, True, False),
    0x1017: (obj1710, True, False),
    0x1018: (obj1810, True, False),
    0x1019: (obj1910, True, False),
    0x100A: (obj0a10, True, True),
    0x100D: (obj0d10, False, True),
    0x2000: (obj0020, False, True),
}
# 0  1  2 3  4 5  6 7  8  9         14 15
# 15 16 95fe 5030 480b 0b 582d3411c3b2 0a100150026d0b
#            ctrl pid  cnt mac         no crypt data
# 0  1  2 3  4 5  6 7  8  9         14 15         20      23    26
# 1a 16 95fe 5858 5b05 a8 ed5e0b38c1a4 0239ff0e35 000000  2f044957
#            ctrl pid  cnt mac         crypt data cnt1..3 mic
# 0  1  2 3  4 5  6 7  8  9         14 15
# 0f 16 95fe 3058 5b05 8b 0a4e0538c1a4 08
#            ctrl pid  cnt mac         cap
#
def parse_xiaomi(self, data, source_mac, rssi):
    # parse BLE message in Xiaomi MiBeacon format
    try:
        firmware = "Xiaomi (MiBeacon)"
        i = 9 # from Frame Counter
        # check for adstruc length
        msg_length = len(data)
        if msg_length < i:
            # Unknown message
            return None, None, None
        # extract frame control bits
        frctrl = data[4] + (data[5]<<8)
        frctrl_mesh = (frctrl >> 7) & 1
        if frctrl_mesh != 0:
            # not support MESH
            return None, None, None
        frctrl_version = frctrl >> 12
        if frctrl_version < 2:
            # not support
            return None, None, None
        frctrl_auth_mode = (frctrl >> 10) & 3
        frctrl_solicited = (frctrl >> 9) & 1
        frctrl_registered = (frctrl >> 8) & 1
        frctrl_object_include = (frctrl >> 6) & 1
        frctrl_capability_include = (frctrl >> 5) & 1
        frctrl_mac_include = (frctrl >> 4) & 1
        frctrl_is_encrypted = (frctrl >> 3) & 1
        frctrl_request_timing = frctrl & 1 # old version
        device_type = data[6] + (data[7]<<8)
        try:
            sensor_type, binary_data = XIAOMI_TYPE_DICT[device_type]
        except KeyError:
            if self.report_unknown == "Xiaomi":
                sensor_type = "XIAOMIx"
                binary_data = False
            raise NoValidError("Device unkown")
        packet_id = data[8]
        sinfo = 'MiVer: ' + str(frctrl_version) + ', DevID: ' + hex(device_type) + ' : ' + sensor_type + ', FnCnt: ' + str(packet_id)
        if frctrl_request_timing != 0:
            sinfo += ', Request timing'
        if frctrl_registered != 0:
            sinfo += ', Registered and bound'
        else:
            sinfo += ', Not bound'
        if frctrl_solicited != 0:
            sinfo += ', Request APP to register and bind'
        if frctrl_auth_mode == 0:
            sinfo += ', Old version certification'
        elif frctrl_auth_mode == 1:
            sinfo += ', Safety certification'
        elif frctrl_auth_mode == 2:
            sinfo += ', Standard certification'
        if frctrl_mac_include != 0:
            i = 15
            if msg_length < i:
                _LOGGER.error("MAC: %s, Invalid adstruct data length!", xiaomi_mac.hex())
                return None, None, None
            xiaomi_mac_i = data[i-6:i]
            xiaomi_mac = xiaomi_mac_i[::-1]
            sinfo += ', MAC: ' + xiaomi_mac.hex()
        else:
            sinfo += ', Not include MAC'
            xiaomi_mac = source_mac
            xiaomi_mac_i = source_mac[::-1]
        try:
            old_adtype = self.adtype[xiaomi_mac]
        except KeyError:
            # start with empty first packet
            old_adtype = 0
        if old_adtype > 2:
            # included advertise package with more precision (pvvx)
            return None, None, None
        try:
            prev_packet = self.lpacket_ids[xiaomi_mac]
        except KeyError:
            # start with empty first packet
            prev_packet = None, None, None
        if prev_packet == packet_id:
            # only process new messages
            return None, None, None
        self.lpacket_ids[xiaomi_mac] = packet_id
        if frctrl_capability_include != 0:
            i += 1
            if msg_length < i:
                _LOGGER.error("MAC: %s, adstruct: %s, Invalid adstruct data length!", xiaomi_mac.hex(), data.hex())
                return None, None, None
            capability_types = data[i-1]
            sinfo += ', Capability: ' + hex(capability_types)
            if (capability_types & 0x20) != 0:
                i += 1
                if msg_length < i:
                    _LOGGER.error("MAC: %s, adstruct: %s, Invalid adstruct data length!", xiaomi_mac.hex(), data.hex())
                    return None, None, None
                capability_io = data[i-1]
                sinfo += ', IO: ' + hex(capability_io)
            #_LOGGER.info(sinfo)
            #return None, None, None
        #_LOGGER.info(sinfo)
        if frctrl_object_include != 0: # contains Object
            if frctrl_is_encrypted != 0:
                firmware = "Xiaomi (Encrypted)"
                # check for minimum length of encrypted advertisement
                if msg_length < i + 9:
                    _LOGGER.info(sinfo)
                    _LOGGER.error("%s, adstruct: %s, Invalid encrypted data length!", sinfo, data.hex())
                    return None, None, None
                packet_id += (data[-7]<<8)+(data[-6]<<16)+(data[-5]<<24)
                # try to find encryption key for current device
                try:
                    key = self.aeskeys[xiaomi_mac_i]
                except KeyError:
                    _LOGGER.error("%s, adstruct: %s, No encryption key found!", sinfo, data.hex())
                    # no encryption key found
                    raise NoValidError("No encryption key found")

                nonce = b"".join([xiaomi_mac_i, data[6:9], data[-7:-4]])
                cipherpayload = data[i:-7]
                token = data[-4:]
                cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
                cipher.update(b"\x11")
                try:
                    payload = cipher.decrypt_and_verify(cipherpayload, token)
                except ValueError as error:
                    _LOGGER.error("%s, Decryption failed(!): %s", sinfo, error)
                    _LOGGER.error("token: %s", token.hex())
                    _LOGGER.error("nonce: %s", nonce.hex())
                    _LOGGER.error("encrypted_payload: %s", data[i:].hex())
                    raise NoValidError("Error decrypting with arguments")
                if payload is None:
                    _LOGGER.error("%s, adstruct: %s, Decrypted payload is None!", sinfo, data.hex())
                    raise NoValidError("Decryption failed")
            else:   # No encryption
                # check minimum advertisement length with data
                firmware = "Xiaomi (No encryption)"
                sinfo += ', No encryption'
                if msg_length < i + 3:
                    _LOGGER.error("%s, adstruct: %s, Invalid Object length", sinfo, data.hex())
                    return None, None, None
                payload = data[i:]
        else: # Does not contain Object
            #_LOGGER.info('%s, Does not contain Object!', sinfo)
            return None, None, None

        result = {
            "rssi": rssi,
            "mac": ''.join('{:02X}'.format(x) for x in xiaomi_mac),
            "type": sensor_type,
            "packet": packet_id,
            "firmware": firmware,
            "data": True,
        }
        binary = False
        measuring = False
        sinfo += ', Object data: ' + payload.hex()
        # loop through parse_xiaomi payload
        xdata_point = 0
        xdata_length = len(payload)
        # assume that the data may have several values of different types
        while xdata_length >= xdata_point + 3:
            xvalue_typecode = payload[xdata_point] + (payload[xdata_point+1]<<8)
            xvalue_length = payload[xdata_point+2]
            xnext_point = xdata_point + 3 + xvalue_length
            if xdata_length < xnext_point:
                #_LOGGER.info('%s, Invalid payload data length!', sinfo)
                break
            xvalue = payload[xdata_point + 3:xnext_point]
            #_LOGGER.info("typecode: %s, xvalue: %s", xvalue_typecode.hex(), xvalue.hex())
            if xvalue_length != 0:
                resfunc, tbinary, tmeasuring = xiaomi_dataobject_dict.get(xvalue_typecode, (None, None, None))

                if resfunc:
                    binary = binary or tbinary
                    measuring = measuring or tmeasuring
                    result.update(resfunc(xvalue))
                else:
                    if self.report_unknown == "Xiaomi":
                       _LOGGER.info('%s, UNKNOWN dataobject in payload!', sinfo)
            xdata_point = xnext_point

        binary = binary and binary_data
        return result, binary, measuring

    except NoValidError as nve:
        _LOGGER.debug("Invalid data: %s", nve)
    return None, None, None


class NoValidError(Exception):
    pass
