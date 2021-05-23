# Parser for ATC BLE advertisements
import logging
import struct

_LOGGER = logging.getLogger(__name__)


def parse_atc(self, data, source_mac, rssi):
    try:
        # check for adstruc length
        msg_length = len(data)
        # Check for the atc1441 or custom format
        if msg_length == 19:
            # Parse BLE message in custom format
            firmware = "ATC (PVVX)"
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
                "opening": (trg & 1) ^ 1}
            measuring = True
            binary = True
            adtype = 3
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
            adtype = 1
        else:
            if self.report_unknown == "ATC":
                _LOGGER.info(
                    "BLE ADV from UNKNOWN ATC SENSOR: RSSI: %s, MAC: %s, ADV: %s",
                    rssi,
                    source_mac.hex(),
                    data.hex()
                )
            _LOGGER.error("Device unkown!")
            return None, None, None
            #raise NoValidError("Device unkown")
        # check for MAC presence in message and in service data
        if atc_mac != source_mac:
            _LOGGER.error("Invalid MAC address!")
            return None, None, None
            #raise NoValidError("Invalid MAC address")
        # check for MAC presence in whitelist, if needed
        if self.discovery is False and atc_mac not in self.whitelist:
            _LOGGER.info("Not in self.whitelist!")
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
