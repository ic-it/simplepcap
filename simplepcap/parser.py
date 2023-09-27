"""This module contains the abstract classes for parsers and parser iterators

The `SomeParser` is used to denote the implementation. You should replace it with the name of
the parser you want to use.

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

    Attributes:
        position:
            Current position in the file
    """

    @abstractmethod
    def __iter__(self) -> ParserIterator:
        raise NotImplementedError

    @abstractmethod
    def __next__(self) -> Packet:
        """Return the next packet in the file

        Raises:
            simplepcap.exceptions.WrongPacketHeaderError: if the packet header is invalid
            simplepcap.exceptions.IncorrectPacketSizeError: if the packet size is incorrect
            simplepcap.exceptions.ReadAfterCloseError: if the file is closed and you try to read a packet from it
            StopIteration: if there are no more packets in the file
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def position(self) -> int:
        raise NotImplementedError


class Parser(ABC):
    """Abstract class for parsers.
    Parser is used to iterate over the packets in a pcap file.
    Parser supports multiple iterators over the same file. Each iterator has its own position in the file.

    Attributes:
        file_path:
            Path to the pcap file
        file_header:
            File header
        is_open:
            True if the file is open
        itearators:
            List of iterators over the packets in the file
            > Note: When iterator raises `StopIteration` it is removed from the list


    Example:
        > Note: Replace `SomeParser` with the name of the parser you want to use

        0. Recommended way to use the parser is to use ["with"](https://peps.python.org/pep-0343/) statement.
        When you iterate over the parser it load the packets one by one from the file.
            ``` py
            from simplepcap.parsers import SomeParser


            with SomeParser(file_path="file.pcap") as parser:
                for i, packet in enumerate(parser):
                    print(i, packet)
            ```

        0. Not recommended way to use the parser is to open and close the file manually.
            ``` py
            from simplepcap.parsers import SomeParser


            parser = SomeParser(file_path="file.pcap")
            parser.open()
            for packet in parser:
                print(packet)
            parser.close()
            ```

        0. You can also use the `get_all_packets()` method to get a list of all packets in the file.
            ``` py
            from simplepcap.parsers import SomeParser


            with SomeParser(file_path="file.pcap") as parser:
                packets = parser.get_all_packets()
            for packet in packets:
                print(packet)
            ```

        0. Not recommended way to use the parser is to open and close the file manually.
            ``` py
            from simplepcap.parsers import SomeParser


            parser = SomeParser(file_path="file.pcap")
            parser.open()
            packets = parser.get_all_packets()
            parser.close()
            for packet in packets:
                print(packet)
            ```

        0. Every iterator has its own position in the file.
            ``` py
            from simplepcap.parsers import SomeParser


            with SomeParser(file_path="file.pcap") as parser:
                iter1 = iter(parser)
                iter2 = iter(parser)
                print(next(iter1)) # packet1
                print(next(iter1)) # packet2
                print(next(iter1)) # packet3
                print(next(iter2)) # packet1
                print(next(iter2)) # packet2
                print(next(iter1)) # packet4
            ```
        > Note: When iterator raises `StopIteration` it is removed from the list
    """

    @abstractmethod
    def __init__(self, *, file_path: Path | str) -> None:
        """Constructor method for Parser

        Args:
            file_path: Path to the pcap file

        Raises:
            simplepcap.exceptions.PcapFileNotFoundError: if the file does not exist
            simplepcap.exceptions.WrongFileHeaderError: if the file header is invalid
            simplepcap.exceptions.UnsupportedFileVersionError: if the file version is not supported
        """
        raise NotImplementedError

    @abstractmethod
    def __iter__(self) -> ParserIterator:
        """Return an iterator over the packets in the file

        Raises:
            simplepcap.exceptions.FileIsNotOpenError: if the file is not open

        Returns:
            Iterator over the packets in the file
        """
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

    @property
    @abstractmethod
    def is_open(self) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def iterators(self) -> list[ParserIterator]:
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
