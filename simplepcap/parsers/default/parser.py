from pathlib import Path

from simplepcap import FileHeader, Packet
from simplepcap.enum import LinkType
from simplepcap.exceptions import PcapFileNotFoundError, FileIsNotOpenError, WrongFileHeaderError
from simplepcap.parser import Parser, ParserIterator
from simplepcap.types import Reserved, Version
from .iterator import DefaultParserIterator


PCAP_FILE_HEADER_SIZE = 24  # in bytes
ALLOWED_MAGIC_NUMBERS = {0xA1B2C3D4, 0xA1B23C4D}


class DefaultParser(Parser):
    def __init__(self, *, file_path: Path | str) -> None:
        self.__file_path = Path(file_path) if isinstance(file_path, str) else file_path
        if not self.__file_path.exists():
            raise PcapFileNotFoundError(file_path=self.__file_path.as_posix())
        self.__file_header = self.__parse_header()
        self.__is_open = False
        self.__iterators = []
        self.__file = None

    def __iter__(self) -> DefaultParserIterator:
        if not self.is_open or self.__file is None:
            raise FileIsNotOpenError(file_path=self.file_path.as_posix())
        return DefaultParserIterator(
            file_header=self.file_header,
            buffered_reader=self.__file,
        )

    def __enter__(self) -> Parser:
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    @property
    def file_path(self) -> Path:
        return self.__file_path

    @property
    def file_header(self) -> FileHeader:
        return self.__file_header

    @property
    def is_open(self) -> bool:
        return self.__is_open

    @property
    def iterators(self) -> list[ParserIterator]:
        return self.__iterators

    def get_all_packets(self) -> list[Packet]:
        return [packet for packet in self]

    def open(self) -> None:
        if self.is_open:
            return
        self.__file = self.file_path.open("rb")
        self.__is_open = True

    def close(self) -> None:
        if not self.is_open or self.__file is None:
            return
        if not self.__file.closed:
            self.__file.close()
        self.__is_open = False

    def __parse_header(self) -> FileHeader:
        if not self.__file_path.exists() or not self.__file_path.is_file():
            raise PcapFileNotFoundError(file_path=self.__file_path.as_posix())
        if self.__file_path.stat().st_size < PCAP_FILE_HEADER_SIZE:
            raise FileIsNotOpenError(file_path=self.__file_path.as_posix())
        with self.__file_path.open("rb") as file:
            header = file.read(PCAP_FILE_HEADER_SIZE)
        magic = int.from_bytes(header[0:4], byteorder="little")
        if magic not in ALLOWED_MAGIC_NUMBERS:
            raise WrongFileHeaderError(
                "Invalid magic number",
                file_path=self.__file_path.as_posix(),
            )
        version = Version(
            major=int.from_bytes(header[4:6], byteorder="little"),
            minor=int.from_bytes(header[6:8], byteorder="little"),
        )
        reserved = Reserved(
            reserved1=header[8:12],
            reserved2=header[12:16],
        )
        snap_len = int.from_bytes(
            header[16:20],
            byteorder="little",
        )
        fcs_f_zero = int.from_bytes(header[20:22], byteorder="little")
        fcs = fcs_f_zero << 3
        fcs_present = bool((fcs_f_zero << 4) & 0b0001)
        link_type = LinkType(int.from_bytes(header[22:24], byteorder="little"))
        return FileHeader(
            magic=magic,
            version=version,
            reserved=reserved,
            snap_len=snap_len,
            fcs_present=fcs_present,
            fcs=fcs,
            link_type=link_type,
        )
