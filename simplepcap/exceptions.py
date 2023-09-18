class SimplePcapError(Exception):
    """Base class for exceptions in this module."""


class PcapFileError(SimplePcapError):
    """Exception raised for errors in the input file."""


class PcapFileNotFoundError(PcapFileError, FileNotFoundError):
    """Exception raised if the file does not exist

    Attributes:
        file_path:
            Path to the pcap file
    """

    def __init__(self, file_path: str) -> None:
        self.__file_path = file_path

    @property
    def file_path(self) -> str:
        return self.__file_path


class WrongFileHeaderError(PcapFileError):
    """Exception raised if the file header is invalid

    Attributes:
        file_path:
            Path to the pcap file
    """

    def __init__(self, file_path: str) -> None:
        self.__file_path = file_path

    @property
    def file_path(self) -> str:
        return self.__file_path
