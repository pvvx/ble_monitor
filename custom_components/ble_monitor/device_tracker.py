""" Passive BLE monitor device tracker"""
# Example config:
# device_tracker:
#   - platform: ble_monitor
#     track_new_devices: true
# look for ble_ devices in known_devices.yaml

import logging
import queue
from collections import namedtuple
from datetime import timedelta

import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import (
    DeviceScanner,
    SOURCE_TYPE_BLUETOOTH_LE,
)
from homeassistant.util import Throttle

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

BLE_PREFIX = "BLE_"


def get_scanner(hass, config):
    """return scanner."""
    return BLEmonitorScanner(hass.data[DOMAIN])


Device = namedtuple('Device', ['mac', 'name', 'last_update'])


class BLEmonitorScanner(DeviceScanner):
    """This class scans for devices using arp-scan."""

    def __init__(self, monitor):
        """Initialize the scanner."""
        self.last_results = []
        self.monitor = monitor
        self.dataqueue = self.monitor.dataqueue["tracker"]
        self.monitor.dumpthread.tracker_enabled = True
        self.success_init = self._update_info()
        _LOGGER.debug("Tracker initialized")

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        _LOGGER.debug("tracker last results %s", self.last_results)
        return [device.mac for device in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device."""
        _LOGGER.debug("get_device_name: %s", device)
        return "ble_" + device.replace(':', "")

    def get_extra_attributes(self, device):
        """Return extra attributes."""
        _LOGGER.debug("get_extra_attributes: %s", device)
        return {"source_type": SOURCE_TYPE_BLUETOOTH_LE}

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """check tracker queue"""
        _LOGGER.debug("Tracker update...")

        last_results = []
        now = dt_util.now()

        while True:
            try:
                device = self.dataqueue.get(block=False)
            except queue.Empty:
                break
            mac = ':'.join('{:02X}'.format(x) for x in device[::-1])
            last_results.append(Device(
                mac.upper(),
                "ble_" + mac.replace(':', "").upper(),
                now
            ))

        self.last_results = last_results
        self.monitor.clear_tracker()
        _LOGGER.debug("Tracker succeeded")
        return True
