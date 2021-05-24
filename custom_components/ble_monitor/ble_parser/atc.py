# Parser for ATC BLE advertisements
import logging
import struct
from Cryptodome.Cipher import AES

_LOGGER = logging.getLogger(__name__)


def parse_atc(self, data, source_mac, rssi):
    try:
        # check for adstruc length
        msg_length = len(data)
        # Check for the atc1441 or custom format
        if msg_length == 19:
            # Parse BLE message in custom format
            firmware = "PVVX (No encryption)"
            sensor_type = "CUSTOM"
            atc_mac = data[4:10]
            atc_mac = atc_mac[::-1]
            (temp, humi, volt, batt, packet_id, trg) = struct.unpack("<hHHBBB", data[10:])
            result = {
                "temperature": temp / 100,
                "humidity": humi / 100,
                "voltage": volt / 1000,
                "battery": batt,
                "switch": (trg >> 1) & 1,
                "opening": (trg ^ 1) & 1}
            measuring = True
            binary = True
            adtype = 39
        elif msg_length == 17:
            # Parse BLE message in ATC format
            firmware = "ATC (ATC1441)"
            sensor_type = "LYWSD03MMC-ATC"
            atc_mac = data[4:10]
            (temp, humi, batt, volt, packet_id) = struct.unpack(">hBBHB", data[10:])
            result = {
                "temperature": temp / 10,
                "humidity": humi,
                "voltage": volt / 1000,
                "battery": batt}
            measuring = True
            binary = False
            adtype = 29
        elif msg_length == 12 or msg_length == 15:
            # Parse BLE message in custom format
            atc_mac = source_mac
            atc_mac_i = atc_mac[::-1]
            # try to find encryption key for current device
            try:
                key = self.aeskeys[atc_mac_i]
            except KeyError:
                _LOGGER.error("MAC: %s, AdStruct: %s,, No encryption key found!", atc_mac.hex(), data.hex())
                # no encryption key found
                return None, None, None
                #raise NoValidError("No encryption key found")
            nonce = b"".join([atc_mac_i, data[:5]])
            cipherpayload = data[5:-4]
            token = data[-4:]
            cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
            cipher.update(b"\x11")
            try:
                payload = cipher.decrypt_and_verify(cipherpayload, token)
            except ValueError as error:
                _LOGGER.error("MAC: %s, AdStruct: %s, Decryption failed(!): %s", atc_mac.hex(), data.hex(), error)
                _LOGGER.error("token: %s", token.hex())
                _LOGGER.error("nonce: %s", nonce.hex())
                _LOGGER.error("encrypted_payload: %s", cipherpayload.hex())
                raise NoValidError("Error decrypting with arguments")
            if payload is None:
                _LOGGER.error("MAC: %s, AdStruct: %s, Decrypted payload is None!", atc_mac.hex(), data.hex())
                raise NoValidError("Decryption failed")
            packet_id = data[4]
            if msg_length == 15:
                firmware = "PVVX (Encrypted)"
                (temp, humi, batt, trg) = struct.unpack("<hHBB", payload)
                if batt > 100:
                    batt = 100
                volt = 2.2 + (3.1 - 2.2) * (batt / 100)
                result = {
                    "temperature": temp/100,
                    "humidity": humi/100,
                    "voltage": volt,
                    "battery": batt,
                    "switch": (trg >> 1) & 1,
                    "opening": (trg ^ 1) & 1 }
                adtype = 39
            else:
                firmware = "ATC (Encrypted)"
                temp = payload[0]/2 - 40.0
                humi = payload[1]/2
                batt = payload[2]&0x7f
                trg = payload[2]>>7
                if batt > 100:
                    batt = 100
                volt = 2.2 + (3.1 - 2.2) * (batt / 100)
                result = {
                    "temperature": temp,
                    "humidity": humi,
                    "voltage": volt,
                    "battery": batt,
                    "switch": trg }
                adtype = 19
            sensor_type = "CUSTOM"
            measuring = True
            binary = True
        else:
            if self.report_unknown == "ATC":
                _LOGGER.info(
                    "BLE ADV from UNKNOWN ATC SENSOR: RSSI: %s, MAC: %s, AdStruct: %s",
                    rssi,
                    source_mac.hex(),
                    data.hex()
                )
            #_LOGGER.error("Device unkown!")
            return None, None, None
            #raise NoValidError("Device unkown")
        # check for MAC presence in message and in service data
        if atc_mac != source_mac:
            _LOGGER.info("MAC: %s, Invalid MAC address!", atc_mac.hex())
            return None, None, None
            #raise NoValidError("Invalid MAC address")
        # check for MAC presence in whitelist, if needed
        if self.discovery is False and atc_mac not in self.whitelist:
            _LOGGER.info("MAC: %s, Not in self.whitelist!", atc_mac.hex())
            return None, None, None
        try:
            old_adtype = self.adtype[atc_mac]
        except KeyError:
            # start with empty first packet
            old_adtype = 0
        try:
            prev_packet = self.lpacket_ids[atc_mac]
        except KeyError:
            # start with empty first packet
            prev_packet = None
        if old_adtype > adtype or prev_packet == packet_id:  # only process new messages
            old_adtype -= 1
            self.adtype[atc_mac] = adtype
            return None, None, None
        self.lpacket_ids[atc_mac] = packet_id
        if old_adtype != adtype:
            self.adtype[atc_mac] = adtype
        result.update({
            "rssi": rssi,
            "mac": ''.join('{:02X}'.format(x) for x in atc_mac),
            "type": sensor_type,
            "packet": packet_id,
            "firmware": firmware,
            "data": True
        })
        return result, binary, measuring

    except NoValidError as nve:
        _LOGGER.debug("Invalid data: %s", nve)
    return None, None, None


class NoValidError(Exception):
    pass
