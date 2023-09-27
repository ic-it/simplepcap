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


class UnsupportedFileVersionError(PcapFileError):
    """Exception raised if the file version is not supported

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


class WrongPacketHeaderError(PcapFileError):
    """Exception raised if the packet header is invalid

    Attributes:
        packet_number:
            Number of the packet

        file_path:
            Path to the pcap file
    """

    def __init__(
        self,
        *args,
        packet_number: int,
        file_path: str,
        **kwargs,
    ) -> None:
        self.__packet_number = packet_number
        self.__file_path = file_path
        super().__init__(*args, **kwargs)

    @property
    def packet_number(self) -> int:
        return self.__packet_number

    @property
    def file_path(self) -> str:
        return self.__file_path


class IncorrectPacketSizeError(PcapFileError):
    """Exception raised if the packet size is incorrect (size in packet header != captured size)

    It is possible only if the file is corrupted.

    Attributes:
        packet_number:
            Number of the packet

        file_path:
            Path to the pcap file
    """

    def __init__(
        self,
        *args,
        packet_number: int,
        file_path: str,
        **kwargs,
    ) -> None:
        self.__packet_number = packet_number
        self.__file_path = file_path
        super().__init__(*args, **kwargs)

    @property
    def packet_number(self) -> int:
        return self.__packet_number

    @property
    def file_path(self) -> str:
        return self.__file_path


class ReadAfterCloseError(PcapFileError):
    """Exception raised if the file is closed and an attempt to read from it is made

    Attributes:
        packet_number:
            Number of the packet that was attempted to be read
        file_path:
            Path to the pcap file
    """

    def __init__(
        self,
        *args,
        packet_number: int,
        file_path: str,
        **kwargs,
    ) -> None:
        self.__packet_number = packet_number
        self.__file_path = file_path
        super().__init__(*args, **kwargs)

    @property
    def packet_number(self) -> int:
        return self.__packet_number

    @property
    def file_path(self) -> str:
        return self.__file_path
