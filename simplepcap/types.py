from dataclasses import dataclass
from datetime import datetime
from simplepcap.enum import LinkType


@dataclass(frozen=True)
class Version:
    """Version of the pcap file format

    Attributes:
        major:
            an unsigned value, giving the number of the current major version of the format.
            The value for the current version of the format is 2.
            This value should change if the format changes in such a way that code that reads the new format could not
            read the old format (i.e., code to read both formats would have to check the version number and use
            different code paths for the two formats) and code that reads the old format could not read the new format.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.8.1)
        minor:
            an unsigned value, giving the number of the current minor version of the format. The value is for the
            current version of the format is 4. This value should change if the format changes in such a way that code
            that reads the new format could read the old format without checking the version number but code that reads
            the old format could not read all files in the new format.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.10.1)
    """

    major: int
    minor: int


@dataclass(frozen=True)
class Reserved:
    """Reserved bytes. Should be 0

    Attributes:
        reserved1:
            not used - SHOULD be filled with 0 by pcap file writers, and MUST be ignored by pcap file readers.
            This value was documented by some older implementations as "gmt to local correction".
            Some older pcap file writers stored non-zero values in this field.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.12.1)

            > Alternatively, the correction time in seconds between GMT (UTC) and the local
            > timezone of the following packet header timestamps. Examples: If the timestamps are in GMT (UTC),
            > thiszone is simply 0. If the timestamps are in Central European time (Amsterdam, Berlin, …) which is
            > GMT + 1:00, thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
            >
            > [Source](https://wiki.wireshark.org/Development/LibpcapFileFormat#global-header)


        reserved2:
            not used - SHOULD be filled with 0 by pcap file writers, and MUST be ignored by pcap file readers.
            This value was documented by some older implementations as "accuracy of timestamps".
            Some older pcap file writers stored non-zero values in this field.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.14.1)

            > Alternatively, in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
            >
            > [Source](https://wiki.wireshark.org/Development/LibpcapFileFormat#global-header)
    """

    reserved1: bytes
    reserved2: bytes


@dataclass(frozen=True)
class FileHeader:
    """Pcap file header

    Attributes:
        magic:
            used to detect the file format itself and the byte ordering.
            The writing application writes `0xa1b2c3d4` with it's native byte ordering format into this field.
            The reading application will read either `0xa1b2c3d4` (identical) or `0xd4c3b2a1` (swapped).
            If the reading application reads the swapped `0xd4c3b2a1` value,
            it knows that all the following fields will have to be swapped too.

            [Source](https://wiki.wireshark.org/Development/LibpcapFileFormat#global-header)
        version:
            version of the pcap file format
        reserved:
            reserved bytes. Should be 0
        snaplen:
            the "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user),
            see: incl_len vs. orig_len below

            [Source](https://wiki.wireshark.org/Development/LibpcapFileFormat#global-header)
        link_type:
            link-layer header type, specifying the type of headers at the beginning of the packet
            (e.g. 1 for Ethernet, see tcpdump.org's link-layer header types page for details);
            this can be various types such as 802.11, 802.11 with various radio information,
            PPP, Token Ring, FDDI, etc.

            [Source](https://wiki.wireshark.org/Development/LibpcapFileFormat#global-header)

            > Note: `network` is a synonym for `link_type`
    """

    magic: int
    version: Version
    reserved: Reserved
    snap_len: int
    link_type: LinkType


@dataclass(frozen=True)
class PacketHeader:
    """Packet record header

    Attributes:
        timestamp:
            Seconds and microseconds when this packet was captured.

            [Source](https://wiki.wireshark.org/Development/LibpcapFileFormat#record-packet-header)
        captured_len:
            the number of bytes of packet data actually captured and saved in the file.
            This value should never become larger than orig_len or the snaplen value of the global header.

            [Source](https://wiki.wireshark.org/Development/LibpcapFileFormat#record-packet-header)
        original_len:
            the length of the packet as it appeared on the network when it was captured.
            If incl_len and orig_len differ, the actually saved packet size was limited by snaplen.

            [Source](https://wiki.wireshark.org/Development/LibpcapFileFormat#record-packet-header)
    """

    timestamp: datetime
    captured_len: int
    original_len: int


@dataclass(frozen=True)
class Packet:
    """Packet

    Attributes:
        header:
            packet header
        data:
            packet data
    """

    header: PacketHeader
    data: bytes
