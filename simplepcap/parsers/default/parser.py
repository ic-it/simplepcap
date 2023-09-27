import atexit
from pathlib import Path

from simplepcap import FileHeader, Packet
from simplepcap.enum import LinkType
from simplepcap.exceptions import (
    PcapFileNotFoundError,
    FileIsNotOpenError,
    UnsupportedFileVersionError,
    WrongFileHeaderError,
)
from simplepcap.parser import Parser, ParserIterator
from simplepcap.types import Reserved, Version
from .iterator import DefaultParserIterator


PCAP_FILE_HEADER_SIZE = 24  # in bytes
ALLOWED_MAGIC_NUMBERS = {0xA1B2C3D4, 0xD4C3B2A1}
SWAP_REQUIRED_MAGIC_NUMBER = 0xD4C3B2A1
SUPPORTED_VERSIONS = {Version(major=2, minor=4)}

# Fields slice
MAGIC = slice(0, 4)
VERSION_MAJOR = slice(4, 6)
VERSION_MINOR = slice(6, 8)
RESERVED1 = slice(8, 12)
RESERVED2 = slice(12, 16)
SNAP_LEN = slice(16, 20)
LINK_TYPE = slice(20, 24)


class DefaultParser(Parser):
    def __init__(self, *, file_path: Path | str) -> None:
        self.__file_path: Path = Path(file_path) if isinstance(file_path, str) else file_path
        if not self.__file_path.exists():
            raise PcapFileNotFoundError(file_path=self.__file_path.as_posix())
        self.__file_header: FileHeader = self.__parse_header()
        self.__is_open: bool = False
        self.__iterators = []
        atexit.register(self.close)

    def __iter__(self) -> DefaultParserIterator:
        if not self.is_open:
            raise FileIsNotOpenError(file_path=self.file_path.as_posix())
        buffered_reader = self.__file_path.open("rb")
        buffered_reader.seek(PCAP_FILE_HEADER_SIZE)
        return DefaultParserIterator(
            file_path=self.__file_path.as_posix(),
            buffered_reader=buffered_reader,
            remove_iterator_callback=self.__remove_iterator,
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
        return list(self)

    def open(self) -> None:
        if self.is_open:
            return
        self.__is_open = True

    def close(self) -> None:
        if not self.is_open:
            return
        for iterator in self.__iterators:
            if not iterator._buffered_reader:
                continue
            iterator._buffered_reader.close()
            iterator._buffered_reader = None
        self.__is_open = False

    def __parse_header(self) -> FileHeader:
        if not self.__file_path.exists() or not self.__file_path.is_file():
            raise PcapFileNotFoundError(file_path=self.__file_path.as_posix())
        if self.__file_path.stat().st_size < PCAP_FILE_HEADER_SIZE:
            raise WrongFileHeaderError(file_path=self.__file_path.as_posix())
        with self.__file_path.open("rb") as file:
            header = file.read(PCAP_FILE_HEADER_SIZE)
        return self.__parse_header_fields(header)

    def __parse_header_fields(self, header: bytes) -> FileHeader:
        assert len(header) == PCAP_FILE_HEADER_SIZE, "Invalid header size"
        magic = int.from_bytes(header[MAGIC], byteorder="little")
        if magic not in ALLOWED_MAGIC_NUMBERS:
            raise WrongFileHeaderError(
                "Invalid magic number",
                file_path=self.__file_path.as_posix(),
            )
        major_version_slice, minor_version_slice = (
            (
                VERSION_MAJOR,
                VERSION_MINOR,
            )
            if magic != SWAP_REQUIRED_MAGIC_NUMBER
            else (
                VERSION_MINOR,
                VERSION_MAJOR,
            )
        )
        version = Version(
            major=int.from_bytes(header[major_version_slice], byteorder="little"),
            minor=int.from_bytes(header[minor_version_slice], byteorder="little"),
        )
        if version not in SUPPORTED_VERSIONS:
            raise UnsupportedFileVersionError(
                f"Got unsupported version: {version}. Supported versions: {SUPPORTED_VERSIONS}",
                file_path=self.__file_path.as_posix(),
            )
        reserved = Reserved(reserved1=header[RESERVED1], reserved2=header[RESERVED2])
        snap_len = int.from_bytes(header[SNAP_LEN], byteorder="little")
        link_type = LinkType(int.from_bytes(header[LINK_TYPE], byteorder="little"))
        return FileHeader(
            magic=magic,
            version=version,
            reserved=reserved,
            snap_len=snap_len,
            link_type=link_type,
        )

    def __remove_iterator(self, iterator: ParserIterator) -> None:
        if iterator in self.__iterators:
            self.__iterators.remove(iterator)
