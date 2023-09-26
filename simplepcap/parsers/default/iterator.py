from datetime import datetime
from io import BufferedReader
from typing import Callable

from simplepcap import Packet, PacketHeader
from simplepcap.parser import ParserIterator

PACKET_HEADER_SIZE = 16  # in bytes

# Fields slice
TIMESTAMP_SEC = slice(0, 4)
TIMESTAMP_USEC = slice(4, 8)
CAPTURED_LEN = slice(8, 12)
ORIGINAL_LEN = slice(12, 16)


class DefaultParserIterator(ParserIterator):
    def __init__(
        self,
        *,
        buffered_reader: BufferedReader,
        remove_iterator_callback: Callable[[ParserIterator], None] | None = None,
    ) -> None:
        self._buffered_reader: BufferedReader | None = buffered_reader
        self.__position = 0
        self.__remove_iterator_callback = remove_iterator_callback or (lambda _: None)

    def __iter__(self) -> ParserIterator:
        return self

    def __next__(self) -> Packet:
        packet = self.__parse_packet()
        if packet is None:
            self.__remove_iterator_callback(self)
            raise StopIteration
        self.__position += 1
        return packet

    @property
    def position(self) -> int:
        return self.__position

    def __parse_packet(self) -> Packet | None:
        assert (
            self._buffered_reader is not None
        ), "Unreachable state: buffered reader is None. Read packet from closed file?"
        raw_header = self._buffered_reader.read(PACKET_HEADER_SIZE)
        if not raw_header:
            return None
        header = self.__parse_packet_header(raw_header)
        data = self._buffered_reader.read(header.captured_len)
        assert len(data) == header.captured_len, "Invalid packet size. Invalid file?"
        return Packet(
            header=header,
            data=data,
        )

    def __parse_packet_header(self, raw_header: bytes) -> PacketHeader:
        assert len(raw_header) == PACKET_HEADER_SIZE, "Invalid header size"
        timestamp_sec = int.from_bytes(raw_header[TIMESTAMP_SEC], byteorder="little")
        timestamp_usec = int.from_bytes(raw_header[TIMESTAMP_USEC], byteorder="little")
        return PacketHeader(
            timestamp=datetime.fromtimestamp(timestamp_sec + timestamp_usec / 1_000_000),
            captured_len=int.from_bytes(raw_header[CAPTURED_LEN], byteorder="little"),
            original_len=int.from_bytes(raw_header[ORIGINAL_LEN], byteorder="little"),
        )
