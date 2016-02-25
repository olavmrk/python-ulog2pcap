#!/usr/bin/env python
import platform
import socket
import struct
import sys

_ULOG_NL_EVENT = 111

class _NetlinkHeader:
    SIZE = 16

    len = None
    type = None
    flags = None
    seq = None
    pid = None

    @staticmethod
    def from_buffer(buf):
        header_buf = buf[0:_NetlinkHeader.SIZE]
        if len(header_buf) < _NetlinkHeader.SIZE:
            raise Exception('Data too small for netlink header.')
        header = _NetlinkHeader()
        (header.len, header.type, header.flags, header.seq, header.pid) = struct.unpack('=IHHII', header_buf)
        return header

    def __str__(self):
        return '_NetlinkHeader(len={len}, type={type}, flags={flags}, seq={seq}, pid={pid})'.format(
            len=self.len, type=self.type, flags=self.flags, seq=self.seq, pid=self.pid)


class _UlogPacket(object):
    _FMT32 = '=LllI16s16sL32sB80s'
    _FMT32_LEN = 4+4+4+4+16+16+4+32+1+80
    _FMT64 = '=QqqI16s16sIQ32sB80s'
    _FMT64_LEN = 8+8+8+4+16+16+4+8+32+1+80

    mark = None
    timestamp_sec = None
    timestamp_usec = None
    hook = None
    indev_name = None
    outdev_name = None
    data_len = None
    prefix = None
    mac = None

    payload = None

    @staticmethod
    def _parse_str_buffer(buf):
        buf_len = buf.find('\0')
        if buf_len == -1:
            return buf
        elif buf_len == 0:
            return None
        else:
            return buf[0:buf_len]

    def _populate_fields(self, mark, timestamp_sec, timestamp_usec, hook, indev_name, outdev_name, data_len, prefix, mac_len, mac):
        self.mark = mark
        self.timestamp_sec = timestamp_sec
        self.timestamp_usec = timestamp_usec
        self.hook = hook
        self.indev_name = _UlogPacket._parse_str_buffer(indev_name)
        self.outdev_name = _UlogPacket._parse_str_buffer(outdev_name)
        self.data_len = data_len
        self.prefix = _UlogPacket._parse_str_buffer(prefix)
        if mac_len > 80:
            raise ValueError('mac_len of packet was larger than 80 bytes.')
        self.mac = mac[0:mac_len]

    @classmethod
    def _from_buffer_32(cls, buf):
        header = buf[0:_UlogPacket._FMT32_LEN]

        r = struct.unpack(_UlogPacket._FMT32, header)

        ret = _UlogPacket()
        ret._populate_fields(
            mark=r[0],
            timestamp_sec=r[1], timestamp_usec=r[2],
            hook=r[3],
            indev_name=r[4], outdev_name=r[5],
            data_len=r[6],
            prefix=r[7],
            mac_len=r[8],
            mac=r[9])
        ret.payload = buf[_UlogPacket._FMT32_LEN:_UlogPacket._FMT32_LEN+ret.data_len]
        if len(ret.payload) != ret.data_len:
            raise Exception('Some payload data missing from netlink message.')

        return ret

    @classmethod
    def _from_buffer_64(cls, buf):
        header = buf[0:_UlogPacket._FMT64_LEN]
        payload = buf[_UlogPacket._FMT64_LEN:]

        r = struct.unpack(_UlogPacket._FMT64, header)

        ret = _UlogPacket()
        ret._populate_fields(
            mark=r[0],
            timestamp_sec=r[1], timestamp_usec=r[2],
            hook=r[3],
            indev_name=r[4], outdev_name=r[5],
            data_len=r[7],
            prefix=r[8],
            mac_len=r[9],
            mac=r[10])
        ret.payload = buf[_UlogPacket._FMT64_LEN:_UlogPacket._FMT64_LEN+ret.data_len]
        if len(ret.payload) != ret.data_len:
            raise Exception('Some payload data missing from netlink message.')
        return ret

    @classmethod
    def _find_from_buffer_impl(cls):
        machine = platform.machine()
        if machine == 'x86_64':
            return _UlogPacket._from_buffer_64
        elif machine == 'i386':
            return _UlogPacket._from_buffer_32
        else:
            raise Exception('Unknown machine: {machine}'.format(machine=machine))

    _from_buffer_impl = None
    @classmethod
    def from_buffer(cls, buf):
        if cls._from_buffer_impl == None:
            cls._from_buffer_impl = _UlogPacket._find_from_buffer_impl()
        return cls._from_buffer_impl(buf)

    def __str__(self):
        elems = []
        if self.mark != 0:
            elems.append('mark={mark}'.format(mark=self.mark))
        ts = float(self.timestamp_sec) + float(self.timestamp_usec) / 1000000.0
        elems.append('time={ts}'.format(ts=ts))
        if self.hook != 0:
            elems.append('hook={hook}'.format(hook=self.hook))
        if self.indev_name:
            elems.append('indev_name=' + self.indev_name)
        if self.outdev_name:
            elems.append('outdev_name=' + self.outdev_name)
        elems.append('data_len={data_len}'.format(data_len=self.data_len))
        if self.prefix:
            elems.append('prefix=' + self.prefix)
        if self.mac:
            mac_hex = ':'.join('{:02x}'.format(ord(b)) for b in self.mac)
            elems.append('mac=' + mac_hex)
        elems.append('payload=({payload_len} bytes)'.format(payload_len=len(self.payload)))
        return '_UlogPacket(' + ', '.join(elems) + ')'

class _UlogReader(object):

    _socket = None

    _queue = None

    def __init__(self, group):
        if group < 1 or group > 32:
            raise ValueError('group must be in the range [1, 32].')
        self._socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_NFLOG)
        self._socket.bind( (0, 1 << (group - 1)) )

    def _load_data(self):
        self._queue = []
        buf = self._socket.recv(131072)
        while len(buf) > 0:
            header = _NetlinkHeader.from_buffer(buf)
            data_end = _NetlinkHeader.SIZE + header.len
            data = buf[_NetlinkHeader.SIZE:data_end]
            if len(data) < header.len - _NetlinkHeader.SIZE:
                raise Exception('Not enough data received in netlink packet.')
            buf = buf[data_end:]

            # Now header contains the netlink header, while data contains the payload.
            # We only care about ULOG_NL_EVENT messages
            if header.type != _ULOG_NL_EVENT:
                continue

            pkt = _UlogPacket.from_buffer(data)
            self._queue.append(pkt)

    def recv(self):
        while self._queue == None or len(self._queue) == 0:
            self._load_data()
        return self._queue.pop(0)

class _PcapWriter(object):
    fp = None

    def __init__(self, fp=sys.stdout):
        self.fp = fp
        self._write_header()

    def _write_header(self):
        magic = 0xa1b2c3d4 #Identifier for PCAP file
        version_major = 2
        version_minor = 4
        thiszone = 0
        sigfigs = 0
        snaplen = 131072 # We don't really know, so we set it to something larger than the maximum
        network = 101 # LINKTYPE_RAW -- contains IPv4 or IPv6 packet.

        header = struct.pack('=IHHiIII',
                             magic,
                             version_major, version_minor,
                             thiszone,
                             sigfigs,
                             snaplen,
                             network)
        self.fp.write(header)
        self.fp.flush()

    @staticmethod
    def _calc_pkt_size(packet):
        if len(packet) < 20:
            # The IPv4 header must be at least 20 bytes,
            # and while the IPv6 header is larger, it also
            # contains the packet size in its first 20 bytes,
            # so we only check for 20 bytes. If the packet is
            # smaller than that, we just return the captured
            # length.
            return len(packet)
        version = ( ord(packet[0]) & 0xf0 ) >> 4
        if version == 4:
            # IPv4
            return (ord(packet[2]) << 8) | ord(packet[3])
        elif version == 6:
            return 40 + ( (ord(packet[5]) << 8) | ord(packet[6]) )
        else:
            # Neither IPv4 or IPv6. Return captured length
            return len(packet)

    def write(self, packet, ts_sec, ts_usec):
        orig_len = _PcapWriter._calc_pkt_size(packet)
        header = struct.pack('=IIII',
                             ts_sec, ts_usec,
                             len(packet),
                             orig_len)
        self.fp.write(header)
        self.fp.write(packet)
        self.fp.flush()

if len(sys.argv) < 2:
    print >>sys.stderr, 'Usage: ulog2pcap.py ULOG-CHANNEL'
    exit(1)

try:
    channel = int(sys.argv[1])
    if channel < 1 or channel > 32:
        raise ValueError()
except:
    print >>sys.stderr, 'ulog2pcap.py: channel must be an integer from 1 to 32 (inclusive).'
    exit(1)


reader = _UlogReader(channel)
writer = _PcapWriter()

try:
    while True:
        pkt = reader.recv()
        writer.write(pkt.payload, pkt.timestamp_sec, pkt.timestamp_usec)
except KeyboardInterrupt:
    pass

