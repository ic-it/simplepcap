from io import BufferedReader
from pathlib import Path

from simplepcap import FileHeader, Packet
from simplepcap.parser import ParserIterator


class DefaultParserIterator(ParserIterator):
    def __init__(self, *, buffered_reader: BufferedReader, file_header: FileHeader) -> None:
        self.__buffered_eader = buffered_reader
        self.__file_header = file_header
        self.__position = 0

    def __iter__(self) -> ParserIterator:
        raise NotImplementedError

    def __next__(self) -> Packet:
        raise NotImplementedError

    @property
    def position(self) -> int:
        return self.__position
