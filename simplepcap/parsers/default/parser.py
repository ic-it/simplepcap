from pathlib import Path

from simplepcap import FileHeader, Packet
from simplepcap.exceptions import PcapFileNotFoundError
from simplepcap.parser import Parser, ParserIterator
from .iterator import DefaultParserIterator


class DefaultParser(Parser):
    def __init__(self, *, file_path: Path | str) -> None:
        self.__file_path = Path(file_path) if isinstance(file_path, str) else file_path
        if not self.__file_path.exists():
            raise PcapFileNotFoundError
        self.__file_header = self.__parse_header()
        self.__is_open = False
        self.__iterators = []

    def __iter__(self) -> DefaultParserIterator:
        raise NotImplementedError

    def __enter__(self) -> Parser:
        raise NotImplementedError

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        raise NotImplementedError

    @property
    def file_path(self) -> Path:
        return self.__file_path

    @property
    def file_header(self) -> FileHeader:
        raise NotImplementedError

    @property
    def is_open(self) -> bool:
        raise NotImplementedError

    @property
    def iterators(self) -> list[ParserIterator]:
        raise NotImplementedError

    def get_all_packets(self) -> list[Packet]:
        raise NotImplementedError

    def open(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def __parse_header(self) -> FileHeader:
        raise NotImplementedError
