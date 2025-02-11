# Parser for Cleargrass or Qingping BLE advertisements
import logging
from struct import unpack

_LOGGER = logging.getLogger(__name__)

def parse_qingping(self, data, source_mac, rssi):
    try:
        # check for adstruc length
        msg_length = len(data)
        if msg_length > 12 and data[4] == 0x08:
            sensor_id = data[5]
            if sensor_id == 0x01:
                firmware = "Cleargrass" # new name 'Qingping'
                sensor_type = "CGG1-Old"
            elif sensor_id == 0x07:
                firmware = "Qingping"
                sensor_type = "CGG1"
            elif sensor_id == 0x09:
                firmware = "Qingping"
                sensor_type = "CGP1W"
            elif sensor_id == 0x0C:
                firmware = "Qingping"
                sensor_type = "CGD1"
            else:
                sensor_type = None

            qingping_mac = data[6:12]
            qingping_mac = qingping_mac[::-1]

            result = {"rssi": rssi}
            xdata_point = 14
            while xdata_point < msg_length:
                xdata_id = data[xdata_point - 2]
                xdata_size = data[xdata_point - 1]
                if xdata_point + xdata_size <= msg_length:
                    if xdata_id == 0x01 and xdata_size == 4:
                        (temp, humi) = unpack("<hH", data[xdata_point:xdata_point+xdata_size])
                        result.update({"temperature": temp / 10, "humidity": humi / 10})
                    elif xdata_id == 0x02 and xdata_size == 1:
                        batt = data[xdata_point]
                        result.update({"battery": batt})
                    elif xdata_id == 0x07 and xdata_size == 2:
                        pres = unpack("<H", data[xdata_point:xdata_point+xdata_size])
                        result.update({"pressure": pres / 10})
                    else:
                        _LOGGER.error("UNKNOWN xdata: %s", data[xdata_point-2:].hex())
                xdata_point += xdata_size + 2
        else:
            sensor_type = None
        if sensor_type == None:
            if self.report_unknown == "Qingping":
                _LOGGER.info(
                    "BLE ADV from UNKNOWN Qingping SENSOR: RSSI: %s, MAC: %s, ADV: %s",
                    rssi,
                    source_mac.hex(),
                    data.hex()
                )
            #raise NoValidError("Device unkown")
            return None, None, None
        # check for MAC presence in message and in service data
        if qingping_mac != source_mac:
            _LOGGER.info("MAC: %s, Invalid MAC address!", qingping_mac.hex())
            return None, None, None
        # check for MAC presence in whitelist, if needed
        if self.discovery is False and qingping_mac not in self.whitelist:
            _LOGGER.info("MAC: %s, Not in self.whitelist!", qingping_mac.hex())
            return None, None, None
        result.update({
            "rssi": rssi,
            "mac": ''.join('{:02X}'.format(x) for x in qingping_mac),
            "type": sensor_type,
            "packet": "none",
            "firmware": firmware,
            "data": True
        })
        return result, False, True

    except NoValidError as nve:
        _LOGGER.debug("Invalid data: %s", nve)
    return None, None, None


class NoValidError(Exception):
    pass
