"""This module contains the abstract classes for parsers and parser iterators

The `SomeParser` is used to denote the implementation. You should replace it with the name of the parser you want to use.

Main Idea of the Parser is to provide an easy way to iterate over the packets in a pcap file.
To ensure safe opening and closing of the file use ["with"](https://peps.python.org/pep-0343/) statement or 
call the `open()` and `close()` methods. (preferred way is to use ["with"](https://peps.python.org/pep-0343/) statement)

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from .types import Packet, FileHeader


class ParserIterator(ABC):
    """Abstract class for parser iterators. This class is used to iterate over the packets in a pcap file

    Parameters:
        file_path:
            Path to the pcap file
        file_header:
            File header

    Attributes:
        position:
            Current position in the file
    """

    @abstractmethod
    def __init__(self, *, file_path: Path, file_header: FileHeader) -> None:
        raise NotImplementedError

    @abstractmethod
    def __iter__(self) -> ParserIterator:
        raise NotImplementedError

    @abstractmethod
    def __next__(self) -> Packet:
        raise NotImplementedError


class Parser(ABC):
    """Abstract class for parsers

    Attributes:
        file_path:
            Path to the pcap file
        file_header:
            File header


    Example 1:
        ``` py
        from simplepcap import SomeParser


        with SomeParser(file_path="file.pcap") as parser:
            for packet in parser:
                print(packet)
        ```

    Example 2:
        ``` py
        from simplepcap import SomeParser


        parser = SomeParser(file_path="file.pcap")
        parser.open()
        for packet in parser:
            print(packet)
        parser.close()
        ```

    Example 3:
        ``` py
        from simplepcap import SomeParser


        with SomeParser(file_path="file.pcap") as parser:
            packets = parser.get_all_packets()
        for packet in packets:
            print(packet)
        ```

    Example 4:
        ``` py
        from simplepcap import SomeParser


        parser = SomeParser(file_path="file.pcap")
        parser.open()
        packets = parser.get_all_packets()
        parser.close()
        for packet in packets:
            print(packet)
        ```
    """

    @abstractmethod
    def __init__(self, *, file_path: Path | str) -> None:
        """Constructor method for Parser

        Args:
            file_path: Path to the pcap file

        Raises:
            simplepcap.exceptions.PcapFileNotFoundError: if the file does not exist
            simplepcap.exceptions.WrongFileHeaderError: if the file header is invalid
        """
        raise NotImplementedError

    @abstractmethod
    def __iter__(self) -> ParserIterator:
        raise NotImplementedError

    @abstractmethod
    def __enter__(self) -> Parser:
        raise NotImplementedError

    @abstractmethod
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        raise NotImplementedError

    @property
    @abstractmethod
    def file_path(self) -> Path:
        raise NotImplementedError

    @property
    @abstractmethod
    def file_header(self) -> FileHeader:
        raise NotImplementedError

    @abstractmethod
    def get_all_packets(self) -> list[Packet]:
        """Return a list of all packet in the file. This method is not recommended for large files"""
        raise NotImplementedError

    @abstractmethod
    def open(self) -> None:
        """Open the file. This method is not needed if the parser is used as a context manager"""
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        """Close the file. This method is not needed if the parser is used as a context manager"""
        raise NotImplementedError
