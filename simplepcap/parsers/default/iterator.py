from datetime import datetime
from io import BufferedReader
from typing import Callable

from simplepcap import Packet, PacketHeader
from simplepcap.exceptions import IncorrectPacketSizeError, ReadAfterCloseError, WrongPacketHeaderError
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
        file_path: str,
        buffered_reader: BufferedReader,
        remove_iterator_callback: Callable[[ParserIterator], None] | None = None,
    ) -> None:
        self._buffered_reader: BufferedReader | None = buffered_reader
        self.__position = -1
        self.__remove_iterator_callback = remove_iterator_callback or (lambda _: None)
        self.__file_path = file_path

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
        if self._buffered_reader is None:
            raise ReadAfterCloseError(
                "Attempt to read from closed file",
                packet_number=self.__position + 1,
                file_path=self.__file_path,
            )
        raw_header = self._buffered_reader.read(PACKET_HEADER_SIZE)
        if not raw_header:
            return None
        header = self.__parse_packet_header(raw_header)
        data = self._buffered_reader.read(header.captured_len)
        if len(data) != header.captured_len:
            raise IncorrectPacketSizeError(
                f"Invalid packet size: {len(data)}. Expected {header.captured_len}",
                packet_number=self.__position + 1,
                file_path=self.__file_path,
            )
        return Packet(
            header=header,
            data=data,
        )

    def __parse_packet_header(self, raw_header: bytes) -> PacketHeader:
        if len(raw_header) != PACKET_HEADER_SIZE:
            raise WrongPacketHeaderError(
                f"Invalid packet header size: {len(raw_header)}. Expected {PACKET_HEADER_SIZE}",
                packet_number=self.__position + 1,
                file_path=self.__file_path,
            )
        timestamp_sec = int.from_bytes(raw_header[TIMESTAMP_SEC], byteorder="little")
        timestamp_usec = int.from_bytes(raw_header[TIMESTAMP_USEC], byteorder="little")
        return PacketHeader(
            timestamp=datetime.fromtimestamp(timestamp_sec + timestamp_usec / 1_000_000),
            captured_len=int.from_bytes(raw_header[CAPTURED_LEN], byteorder="little"),
            original_len=int.from_bytes(raw_header[ORIGINAL_LEN], byteorder="little"),
        )
