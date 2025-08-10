# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import errno
import struct
import time

import usb._objfinalizer
import usb.core
import usb.util

from . import exceptions
from .commands import DFU, STM32L4


class DFUDevice:
    dev: usb.core.Device
    intNum: int
    intf: usb.core.Interface
    # def __init__(self):
    #     pass

    @staticmethod
    def addr2list(a):
        return [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]

    @staticmethod
    def addr2block(addr, size):
        addr -= 0x08000000
        addr //= size
        addr += 2
        return addr

    @staticmethod
    def block2addr(addr, size):
        addr -= 2
        addr *= size
        addr += 0x08000000
        return addr

    def find(self, altsetting: int = 0, ser: str | None = None, dev: usb.core.Device | None = None) -> usb.core.Device:
        if dev is not None:
            self.dev = dev
        else:
            devs = usb.core.find(idVendor=0x0483, idProduct=0xDF11, find_all=True)
            if devs is None:
                raise RuntimeError("No ST DFU devices found.")
            _devs = [devs] if isinstance(devs, usb.core.Device) else devs

            if ser is not None:
                eligible = [d for d in _devs if ser == usb.util.get_string(d, d.serial_number)]
            else:
                eligible = list(_devs)

            if len(eligible) > 1:
                raise exceptions.NonUniqueDeviceError
            if len(eligible) == 0:
                raise RuntimeError("No ST DFU devices found.")
            self.dev = eligible[0]

        self.dev.set_configuration()

        for cfg in self.dev.configurations():
            for intf_num, intf in enumerate(cfg.interfaces()):
                try:
                    alt_intf = cfg[(intf_num, altsetting)]
                except usb.core.USBError:
                    continue  # This altsetting doesn't exist for this interface
                self.dev.set_interface_altsetting(interface=intf_num,
                                                alternate_setting=altsetting)
                self.intf = alt_intf
                self.intNum = intf_num
                return self.dev

        # self.dev.set_interface_altsetting(0, altsetting)
        # cfg = self.dev.get_active_configuration()
        # self.intf = cfg[(0, altsetting)]
        # self.intNum = 0
        # return self.dev

        raise RuntimeError("No ST DFU alternate-%d found." % altsetting)

    # Main memory == 0
    # option bytes == 1
    def set_alt(self, altsetting : int) -> None:
        for cfg in self.dev.configurations():
            for intf_num, intf in enumerate(cfg.interfaces()):
                try:
                    alt_intf = cfg[(intf_num, altsetting)]
                except usb.core.USBError:
                    continue  # This altsetting doesn't exist for this interface
                self.dev.set_interface_altsetting(interface=intf_num, alternate_setting=altsetting)
                self.intf = alt_intf
                self.intNum = intf_num

    def init(self) -> None:
        if self.state() == DFU.state.ERROR:
            self.clear_status()

    def close(self) -> None:
        pass

    def get_status(self) -> DFU.status:
        tries = 3
        while True:
            try:
                # bmReqType, bmReq, wValue, wIndex, data/size
                s = self.dev.ctrl_transfer(DFU.type.RECEIVE, DFU.bmReq.GETSTATUS, 0, self.intNum, 6)
                break
            except usb.core.USBError as e:
                if e.errno == errno.EPIPE:
                    if tries > 0:
                        tries -= 1
                        time.sleep(0.01)
                    else:
                        # do not pass on EPIPE which might be swallowed by 'click'
                        raise RuntimeError("Failed to get status from DFU.")
                else:
                    raise
        return DFU.status(s)

    def state(self) -> DFU.state:
        return self.get_status().state

    def clear_status(self):
        # bmReqType, bmReq, wValue, wIndex, data/size
        self.dev.ctrl_transfer(DFU.type.SEND, DFU.bmReq.CLRSTATUS, 0, self.intNum, None)

    def upload(self, block, size):
        """
        address is  ((block – 2) × size) + 0x08000000
        """
        # bmReqType, bmReq, wValue, wIndex, data/size
        return self.dev.ctrl_transfer(DFU.type.RECEIVE, DFU.bmReq.UPLOAD, block, self.intNum, size)

    def set_addr(self, addr):
        # must get_status after to take effect
        return self.dnload(0x0, [0x21] + DFUDevice.addr2list(addr))

    def dnload(self, block, data):
        # bmReqType, bmReq, wValue, wIndex, data/size
        return self.dev.ctrl_transfer(DFU.type.SEND, DFU.bmReq.DNLOAD, block, self.intNum, data)

    def erase(self, a):
        d = [0x41, a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]
        return self.dnload(0x0, d)

    def mass_erase(self):
        # self.set_addr(0x08000000)
        # self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        # assert(DFU.state.DOWNLOAD_IDLE == self.state())
        self.dnload(0x0, [0x41])
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        assert DFU.state.DOWNLOAD_IDLE == self.state()

    def write_page(self, addr, data):
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            raise RuntimeError("DFU device not in correct state for writing memory.")

        addr = DFUDevice.addr2block(addr, len(data))
        # print('flashing %d bytes to block %d/%08x...' % (len(data), addr,oldaddr))

        self.dnload(addr, data)
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        assert DFU.state.DOWNLOAD_IDLE == self.state()

    def read_mem(self, addr, size):
        addr = DFUDevice.addr2block(addr, size)

        if self.state() not in (DFU.state.IDLE, DFU.state.UPLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.UPLOAD_IDLE):
            raise RuntimeError("DFU device not in correct state for reading memory.")

        return self.upload(addr, size)

    def block_on_state(self, state: DFU.state) -> None:
        s = self.get_status()
        while s.state == state:
            time.sleep(s.timeout / 1000.0)
            s = self.get_status()

    def read_option_bytes(self):
        ptr = 0x1FFF7800  # option byte address for STM32l432
        self.set_addr(ptr)
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        m = self.read_mem(0, 16)
        return m

    def write_option_bytes(self, m) -> None:
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        try:
            m = self.write_page(0, m)
            self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        except OSError:
            print("Warning: OSError with write_page")

    def prepare_options_bytes_detach(self) -> None:

        # Necessary to prevent future errors...
        m = self.read_mem(0, 16)
        self.write_option_bytes(m)
        #

        m = self.read_option_bytes()
        op = struct.unpack("<L", m[:4])[0]
        oldop = op
        op |= STM32L4.options.nBOOT0
        op &= ~STM32L4.options.nSWBOOT0

        if oldop != op:
            print("Rewriting option bytes...")
            m = struct.pack("<L", op) + m[4:]
            self.write_option_bytes(m)

    def detach(self) -> DFU.status:
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            raise RuntimeError("DFU device not in correct state for detaching.")
        # self.set_addr(0x08000000)
        # self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        # assert(DFU.state.DOWNLOAD_IDLE == self.state())
        self.dnload(0x0, [])
        return self.get_status()
        # return self.dev.ctrl_transfer(DFU.type.SEND, DFU.bmReq.DETACH, 0, self.intNum, None)


def find(dfu_serial: str | None = None, attempts: int = 8, raw_device: usb.core.Device | None = None, altsetting: int = 1) -> DFUDevice:
    """dfu_serial is the ST bootloader serial number.

    It is not directly the ST chip identifier, but related via
    https://github.com/libopencm3/libopencm3/blob/master/lib/stm32/desig.c#L68
    """
    for i in range(attempts):
        dfu = DFUDevice()
        try:
            dfu.find(ser=dfu_serial, dev=raw_device, altsetting=altsetting)
            return dfu
        except RuntimeError:
            time.sleep(0.25)

    # return None
    raise Exception("no DFU found")


def find_all() -> list[DFUDevice]:
    st_dfus = usb.core.find(idVendor=0x0483, idProduct=0xDF11, find_all=True)
    if st_dfus is None:
        return []
    _st_dfus = [st_dfus] if isinstance(st_dfus, usb.core.Device) else st_dfus
    return [find(raw_device=st_dfu) for st_dfu in _st_dfus]


def hot_patch_windows_libusb() -> None:
    # hot patch for windows libusb backend
    olddel = usb._objfinalizer._AutoFinalizedObjectBase.__del__

    def newdel(self):
        try:
            olddel(self)
        except OSError:
            pass

    usb._objfinalizer._AutoFinalizedObjectBase.__del__ = newdel
