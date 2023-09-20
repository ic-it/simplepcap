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
        reserved2:
            not used - SHOULD be filled with 0 by pcap file writers, and MUST be ignored by pcap file readers.
            This value was documented by some older implementations as "accuracy of timestamps".
            Some older pcap file writers stored non-zero values in this field.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.14.1)
    """

    reserved1: bytes
    reserved2: bytes


@dataclass(frozen=True)
class FileHeader:
    """Pcap file header

    Attributes:
        magic:
            an unsigned magic number, whose value is either the hexadecimal number `0xA1B2C3D4` or the
            hexadecimal number `0xA1B23C4D`.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.2.1)
        version:
            version of the pcap file format
        reserved:
            reserved bytes. Should be 0
        snap_len:
            an unsigned value indicating the maximum number of octets captured from each packet.
            The portion of each packet that exceeds this value will not be stored in the file.
            This value MUST NOT be zero; if no limit was specified, the value should be a number greater
            than or equal to the largest packet length in the file.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.16.1)
        link_type:
            a 16-bit unsigned value that defines the link layer type of packets in the file.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.18.1)
        fcs_present: _Frame Cyclic Sequence (FCS) present_.
            if the "f" bit is set, then the 3 FCS bits provide the number of 16-bit (2 byte) words of FCS that
            are appended to each packet.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-4-5.20.1)
    """

    magic: bytes
    version: Version
    reserved: Reserved
    snap_len: int
    link_type: LinkType
    fcs_present: bool


@dataclass(frozen=True)
class PacketHeader:
    """Packet record header

    Attributes:
        timestamp:
            seconds and fraction of a seconds values of a timestamp.

            The seconds value is a 32-bit unsigned integer that represents the number of seconds that have elapsed
            since 1970-01-01 00:00:00 UTC, and the microseconds or nanoseconds value represents the number of
            microseconds or nanoseconds that have elapsed since that seconds.

            Whether the value represents microseconds or nanoseconds is specified by the magic number in the
            File Header.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-5-5.2.1)
        captured_len:
            an unsigned value that indicates the number of octets captured from the packet
            (i.e. the length of the Packet Data field). It will be the minimum value among the Original Packet Length
            and the snapshot length for the interface (SnapLen, defined in Figure 1).

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-5-5.8.1)
        original_len:
            an unsigned value that indicates the actual length of the packet when it was transmitted on the network.
            It can be different from the Captured Packet Length if the packet has been truncated by the capture process.

            [Source](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html#section-5-5.10.1)
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
