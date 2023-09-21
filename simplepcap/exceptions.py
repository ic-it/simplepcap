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

    def __init__(
        self,
        *args,
        file_path: str,
        **kwargs,
    ) -> None:
        self.__file_path = file_path
        super().__init__(*args, **kwargs)

    @property
    def file_path(self) -> str:
        return self.__file_path


class WrongFileHeaderError(PcapFileError):
    """Exception raised if the file header is invalid

    Attributes:
        file_path:
            Path to the pcap file
    """

    def __init__(
        self,
        *args,
        file_path: str,
        **kwargs,
    ) -> None:
        self.__file_path = file_path
        super().__init__(*args, **kwargs)

    @property
    def file_path(self) -> str:
        return self.__file_path


class FileIsNotOpenError(PcapFileError):
    """Exception raised if the file is not open

    Attributes:
        file_path:
            Path to the pcap file
    """

    def __init__(
        self,
        *args,
        file_path: str,
        **kwargs,
    ) -> None:
        self.__file_path = file_path
        super().__init__(*args, **kwargs)

    @property
    def file_path(self) -> str:
        return self.__file_path
