# -*- coding: utf-8 -*-
import ctypes
import fcntl
import os
import string
import struct


__all__ = ["BPF"]

##################################################################
# CONSTANTS / GLOBALS
# BPF SPECIFIC CONSTANTS
BPF_LD = 0x00
BPF_H = 0x08
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06
ETHERTYPE_ETHERCAT = 0x8888

OSX_BPF_DEVICES = "sysctl debug.bpf_maxdevices"
OSX_NETWORKSETUP_LIST = "networksetup -listallhardwareports"
OSX_NETWORKSETUP_GET_MAC = "networksetup -getmacaddress"
OSX_INTERFACE_DEV_QUERY_STR = "Device:"
OSX_INTERFACE_ADDRESS_QUERY_STR = "Ethernet Address:"

"""
Linux ioctl numbers made easy

size can be an integer or format string compatible with struct module

for example include/linux/watchdog.h:

#define WATCHDOG_IOCTL_BASE     'W'

struct watchdog_info {
        __u32 options;          /* Options the card/driver supports */
        __u32 firmware_version; /* Firmware version of the card */
        __u8  identity[32];     /* Identity of the board */
};

#define WDIOC_GETSUPPORT  _IOR(WATCHDOG_IOCTL_BASE, 0, struct watchdog_info)

becomes:

WDIOC_GETSUPPORT = _IOR(ord('W'), 0, "=II32s")
"""
# constant for linux portability
_IOC_NRBITS = 8
_IOC_TYPEBITS = 8

# architecture specific
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRMASK = (1 << _IOC_NRBITS) - 1
_IOC_TYPEMASK = (1 << _IOC_TYPEBITS) - 1
_IOC_SIZEMASK = (1 << _IOC_SIZEBITS) - 1
_IOC_DIRMASK = (1 << _IOC_DIRBITS) - 1

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def _IOC(dir, type, nr, size):
    if isinstance(size, str) or isinstance(size, unicode):
        size = struct.calcsize(size)
    return dir  << _IOC_DIRSHIFT  | \
           type << _IOC_TYPESHIFT | \
           nr   << _IOC_NRSHIFT   | \
           size << _IOC_SIZESHIFT


def _IO(type, nr):
    return _IOC(_IOC_NONE, type, nr, 0)


def _IOR(type, nr, size):
    return _IOC(_IOC_READ, type, nr, size)


def _IOW(type, nr, size):
    return _IOC(_IOC_WRITE, type, nr, size)


def _IOWR(type, nr, size):
    return _IOC(_IOC_READ | _IOC_WRITE, type, nr, size)


class bpf_insn(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_int)]


class bpf_program(ctypes.Structure):
    _fields_ = [(".bf_len", ctypes.c_uint), (".bf_insns", ctypes.POINTER(bpf_insn))]


def eth_aton(mac):
    address = ""
    temp = string.split(mac, ':')
    mac = string.join(temp, '')
    for i in range(0, len(mac), 2):
        address = "".join([address, struct.pack('B', int(mac[i:i + 2], 16))], )
    return address


def conv_octet(octet):
    res = ""
    factor = 16
    for i in range(0, 2):  # max ff = 15*16+15
        div = int(octet / factor)
        res += "%x" % div
        octet -= div * 16
        factor /= 16
    return res


def eth_rev_aton(hexstr, lang=6):
    res = ""
    for i in range (0, lang):
        if res:
            res += ':'
        res += conv_octet(ord(hexstr[i]))
    return res


class BPF(object):

    def __init__(self, protocol=None):
        self.protocol = None
        self.socket = None
        # get maximum number of BPF devices
        bpf_num_str = os.popen(OSX_BPF_DEVICES).read()

        if not "debug.bpf_maxdevices:" in bpf_num_str:
            print "[-] ERROR: failed to get the amount of bpf devices"
            exit (1)
        else:
            bpf_num_str = bpf_num_str[22:]

        bpf_num = int(bpf_num_str)

        # try to open (binary read and write) the /dev/bpfx device
        for i in range(bpf_num):
            bpf_device = "/dev/bpf%d" % i

            if not os.path.exists(bpf_device):
                print "[-] ERROR: no suitable /dev/bpfx device found, last one tried: %s" % bpf_device
                exit (1)

            try:
                self.socket = open(bpf_device, "rb+")
                break
            except IOError as ioe:
                if ioe.errno == 13:
                    print "[-] ERROR: Permission denied"
                    exit (1)
                if ioe.errno == 16: # resource busy -> try next one
                    pass

        if self.socket is None:
            print "[-] ERROR: could not open any /dev/bpfx devices. Exiting..."
            exit (1)
        if protocol is not None:
            if isinstance(protocol, list):
                self.protocol = []
                self.protocol.extend(protocol)
            else:
                self.protocol = []
                self.protocol.append(protocol)

    def bind(self, interface):
        self.buffer_size = self.__init_and_bind_bpf_socket__(interface)
        if self.buffer_size < 1:
          print "[-] ERROR: the determined buffer size is not valid (too small). Exiting..."
          exit (1)

    def send(self, msg):
        os.write(self.socket.fileno(), msg)

    def recv(self, buf_size):
        while 1:
            buf = ""
            try:
                buf = os.read(self.socket.fileno(), self.buffer_size)
            except:
                print "[-] ERROR encountered while reading from BPF device"
                exit (1)
            msg = buf[18:]
            dst = buf[18:24]
            # src = buf[24:30]

            if dst == self.mac_address:
                pro = struct.unpack('!H', buf[30:32])[0]
                if self.protocol and pro in self.protocol:
                    return msg

    def __osx_is_interface_valid__(self, interface):
        hardware_list = ""

        try:
            hardware_list = os.popen(OSX_NETWORKSETUP_LIST).read()
        except:
            print "[-] ERROR: an error was encountered while querying all hardware ports"
            exit (1)

        if not hardware_list:
            print "[-] ERROR: hardware port list is empty, can't proceed"
            exit (1)

        found = False

        lines = hardware_list.split("\n")

        for line in lines:
            if line.startswith(OSX_INTERFACE_DEV_QUERY_STR + " " + interface):
                found = True
                break

        if not found:
            print "[-] ERROR: interface name was not found in hardware ports list"
            exit (1)

        if interface.find (';') != -1 or \
           interface.find ('|') != -1 or \
           interface.find (',') != -1 or \
           interface.find ('$') != -1 or \
           interface.find (':') != -1:
            print "[-] ERROR: invalid interface name detected. Exiting..."
            exit (1)

    def get_hardware_address(self, interface):
        # security check (always be paranoia !!! better safe than sorry!)
        self.__osx_is_interface_valid__(interface)

        try:
            info = os.popen(OSX_NETWORKSETUP_GET_MAC + " " + interface).read()
        except:
            print "[-] ERROR: could not get the hardware MAC address of interface '%s'" % interface
            exit(1)

        if not info:
            print "[-] ERROR: could not find the specified interface in the networksetup list"
            exit(1)

        if info.find(OSX_INTERFACE_DEV_QUERY_STR + " " + interface) == -1:
            print "[-] ERROR: output of the networksetup list does not contain the interface '%s'" % interface
            exit(1)

        address_pos = info.find (OSX_INTERFACE_ADDRESS_QUERY_STR + " ")

        if address_pos == -1:
            print "[-] ERROR: output of the networksetup list does not contain the valid 'Ethernet Address'"
            exit(1)

        query_str_len = len (OSX_INTERFACE_ADDRESS_QUERY_STR)
        substr_start  = address_pos + query_str_len + 1
        substr_stop   = substr_start + 17

        mac_address = info[substr_start:substr_stop]

        return mac_address

    def get_mac_address(self, interface):
        self.mac_address = ""
        self.hardware_address = self.get_hardware_address(interface)
        for address_part in self.hardware_address.split(":"):
                address_part = int(address_part, 16)
                self.mac_address += chr(address_part)
        return self.mac_address

    def __getBPFProgram__(self):
        num_insn = 4

        # insn 1
        stmt1 = bpf_insn()
        stmt1.code = BPF_LD + BPF_H + BPF_ABS
        stmt1.jt = 0
        stmt1.jf = 0
        stmt1.k = 12

        # insn 2
        jump1 = bpf_insn()
        jump1.code = BPF_JMP + BPF_JEQ + BPF_K
        jump1.jt = 0
        jump1.jf = 1
        jump1.k = ETHERTYPE_ETHERCAT
        jump1.k = 0

        # insn 3
        stmt2 = bpf_insn()
        stmt2.code = BPF_RET + BPF_K
        stmt2.jt = 0
        stmt2.jf = 0
        stmt2.k = -1

        # insn 4
        stmt3 = bpf_insn()
        stmt3.code = BPF_RET + BPF_K
        stmt3.jt = 0
        stmt3.jf = 0
        stmt3.k = 0

        program = bpf_program()

        program.bf_len   = num_insn
        program.bf_insns = (bpf_insn * num_insn) (stmt1, jump1, stmt2, stmt3)

        return program

    def __init_and_bind_bpf_socket__(self, interface):
        # BIOCSBLEN - set required buffer length for reads
        # _IOWR(B,102, u_int)
        ioc = _IOWR(ord('B'), 102, 'I')
        set_buf_size = struct.pack('I', 128)
        (_,) = struct.unpack("I", fcntl.ioctl(self.socket.fileno(), ioc, set_buf_size))

        # BIOCSETIF - sets the hardware interface associated with the bpf file
        # _IOW (B, 108, struct ifreq)

        ioc = 0x80000000 | (32 << 16) | (ord('B') <<  8) | 108
        buf = struct.pack('32s', interface)

        try:
            fcntl.ioctl(self.socket.fileno(), ioc, buf)
        except:
            print "[-] ERROR: could not bind BPF device to interface."
            exit(1)

        # BIOCIMMEDIATE - enables immediate mode
        # _IOW ('B', 112, u_int)

        ioc = 0x80000000 | (4 << 16) | (ord('B') << 8) | 112
        buf = struct.pack('I', 1)
        fcntl.ioctl(self.socket.fileno(), ioc, buf)

        # BIOCSHDRCMPLT - disable to set link level source address automatically
        # _IOR ('B', 117, u_int)

        ioc = 0x80000000 | (4 << 16) | (ord('B') << 8) | 117
        buf = struct.pack('I', 1)
        fcntl.ioctl(self.socket.fileno(), ioc, buf)

        # BIOCGBLEN - get required buffer length for reads
        # _IOR (B, 102, u_int)

        ioc = 0x40000000 | (4 << 16) | (ord('B') << 8) | 102
        buf = struct.pack('i', 0)
        (buf_size,) = struct.unpack("I",
                                    fcntl.ioctl(self.socket.fileno(), ioc, buf))

        # BIOCSORTIMEOUT - set the read timeout
        # _IOW ('B', 109, struct timeval50)

        ioc = 0x80000000 | (8 << 16) | (ord('B') << 8) | 109
        buf = struct.pack('II', 5, 0)
        fcntl.ioctl(self.socket.fileno(), ioc, buf)

        # BIOCSETF - set a filter/program
        # _IOW ('B', 103, struct bpf_program)
        # program = self.__getBPFProgram__()
        # ioc = 0x80000000 | (8 << 16) | (ord('B') << 8) | 103
        # fcntl.ioctl(self.socket.fileno(), ioc, program)

        # BIOCFLUSH
        # _IO(ord('B'), 104)

        return buf_size
