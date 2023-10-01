class SimplePcapError(Exception):
    """Base class for exceptions in this module."""


class PcapFileError(SimplePcapError):
    """Exception raised for errors in the input file."""


class PcapFileNotFoundError(PcapFileError, FileNotFoundError):
    def __init__(self, *args, file_path: str, **kwargs) -> None:
        self.file_path = file_path
        super().__init__(*args, **kwargs)


class WrongFileHeaderError(PcapFileError):
    def __init__(self, *args, file_path: str, **kwargs) -> None:
        self.file_path = file_path
        super().__init__(*args, **kwargs)


class FileIsNotOpenError(PcapFileError):
    def __init__(self, *args, file_path: str, **kwargs) -> None:
        self.file_path = file_path
        super().__init__(*args, **kwargs)


class UnsupportedFileVersionError(PcapFileError):
    def __init__(self, *args, file_path: str, **kwargs) -> None:
        self.file_path = file_path
        super().__init__(*args, **kwargs)


class WrongPacketHeaderError(PcapFileError):
    def __init__(self, *args, packet_number: int, file_path: str, **kwargs) -> None:
        self.packet_number = packet_number
        self.file_path = file_path
        super().__init__(*args, **kwargs)


class IncorrectPacketSizeError(PcapFileError):
    def __init__(self, *args, packet_number: int, file_path: str, **kwargs) -> None:
        self.packet_number = packet_number
        self.file_path = file_path
        super().__init__(*args, **kwargs)


class ReadAfterCloseError(PcapFileError):
    def __init__(self, *args, packet_number: int, file_path: str, **kwargs) -> None:
        self.packet_number = packet_number
        self.file_path = file_path
        super().__init__(*args, **kwargs)
