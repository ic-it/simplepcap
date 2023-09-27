import io
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from simplepcap import Packet
from simplepcap.exceptions import IncorrectPacketSizeError, ReadAfterCloseError, WrongPacketHeaderError
from simplepcap.parsers import DefaultParserIterator


PACKET_HEADER_SIZE = 16

# Mockup data for testing
MOCK_PACKET_BODY = (
    b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00"
    b"\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11\x00\x00\x7f\x00\x00\x01"
    b"\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)
TIMESTAMP = datetime(2001, 1, 2, 3, 4, 5, 123456)
TIMESTAMP_SEC_INT = int(datetime(2001, 1, 2, 3, 4, 5).timestamp())
TIMESTAMP_USEC_INT = 123456
VALID_TIMESTAMP_SEC = TIMESTAMP_SEC_INT.to_bytes(4, byteorder="little")
VALID_TIMESTAMP_USEC = TIMESTAMP_USEC_INT.to_bytes(4, byteorder="little")
VALID_CAPTURED_LEN = len(MOCK_PACKET_BODY).to_bytes(4, byteorder="little")
VALID_ORIGINAL_LEN = VALID_CAPTURED_LEN  # same for this case
MOCK_HEADER = VALID_TIMESTAMP_SEC + VALID_TIMESTAMP_USEC + VALID_CAPTURED_LEN + VALID_ORIGINAL_LEN

INVALID_CAPTURED_LEN = (1000).to_bytes(4, byteorder="little")
INVALID_ORIGINAL_LEN = (2000).to_bytes(4, byteorder="little")
INVALID_HEADER = VALID_TIMESTAMP_SEC + VALID_TIMESTAMP_USEC + INVALID_CAPTURED_LEN + INVALID_ORIGINAL_LEN

TEST_FILE_PATH = "test.pcap"


@pytest.fixture
def mock_buffered_reader():
    return MagicMock(spec=io.BufferedReader)


@pytest.fixture
def mock_remove_iterator_callback():
    return MagicMock()


@pytest.fixture
def default_parser_iterator(mock_buffered_reader):
    return DefaultParserIterator(file_path=TEST_FILE_PATH, buffered_reader=mock_buffered_reader)


@pytest.fixture
def default_parser_iterator_with_callback(mock_buffered_reader, mock_remove_iterator_callback):
    return DefaultParserIterator(
        file_path=TEST_FILE_PATH,
        buffered_reader=mock_buffered_reader,
        remove_iterator_callback=mock_remove_iterator_callback,
    )


def test_default_parser_iterator_parses_multiple_packets(default_parser_iterator, mock_buffered_reader):
    # Create a mock buffered reader that will return two packets
    mock_buffered_reader.read.side_effect = [
        MOCK_HEADER,
        MOCK_PACKET_BODY,  # First packet
        MOCK_HEADER,
        MOCK_PACKET_BODY,  # Second packet
        b"",  # Empty data to signal end of file
    ]

    packets = list(default_parser_iterator)
    assert len(packets) == 2
    assert isinstance(packets[0], Packet)
    assert isinstance(packets[1], Packet)


def test_default_parser_iterator_correct_header_parsing(default_parser_iterator, mock_buffered_reader):
    # Create a mock buffered reader that will return one packet
    mock_buffered_reader.read.side_effect = [
        MOCK_HEADER,
        MOCK_PACKET_BODY,
        b"",  # Empty data to signal end of file
    ]

    packet = next(default_parser_iterator)
    header = packet.header

    assert header.timestamp == TIMESTAMP
    assert header.captured_len == len(MOCK_PACKET_BODY)
    assert header.original_len == len(MOCK_PACKET_BODY)


def test_default_parser_iterator_invalid_header_size(default_parser_iterator, mock_buffered_reader):
    # Set a header size different from PACKET_HEADER_SIZE
    mock_buffered_reader.read.return_value = b"InvalidHeaderSize"

    with pytest.raises(WrongPacketHeaderError) as excinfo:
        next(default_parser_iterator)
    assert excinfo.value.packet_number == 0
    assert excinfo.value.file_path == TEST_FILE_PATH


def test_default_parser_iterator_remove_iterator_callback(
    default_parser_iterator_with_callback,
    mock_buffered_reader,
    mock_remove_iterator_callback,
):
    # Create a mock buffered reader that will return one packet
    mock_buffered_reader.read.side_effect = [
        MOCK_HEADER,
        MOCK_PACKET_BODY,
        b"",  # Empty data to signal end of file
    ]

    # Iterate over the iterator
    next(default_parser_iterator_with_callback)
    with pytest.raises(StopIteration):
        next(default_parser_iterator_with_callback)

    # Check that the callback was called
    mock_remove_iterator_callback.assert_called_once()


def test_default_parser_iterator_invalid_captured_len(default_parser_iterator, mock_buffered_reader):
    # Set an invalid captured_len
    mock_buffered_reader.read.side_effect = [
        INVALID_HEADER,
        MOCK_PACKET_BODY,
        b"",  # Empty data to signal end of file
    ]

    with pytest.raises(IncorrectPacketSizeError) as excinfo:
        next(default_parser_iterator)
    assert excinfo.value.packet_number == 0
    assert excinfo.value.file_path == TEST_FILE_PATH


def test_read_after_close_error(default_parser_iterator, mock_buffered_reader):
    # Set a mock buffered reader that will return one packet
    mock_buffered_reader.read.side_effect = [
        MOCK_HEADER,
        MOCK_PACKET_BODY,
        b"",  # Empty data to signal end of file
    ]

    # Iterate over the iterator
    next(default_parser_iterator)

    # Close the iterator
    default_parser_iterator._buffered_reader = None

    # Try to read from the iterator
    with pytest.raises(ReadAfterCloseError) as excinfo:
        next(default_parser_iterator)
    assert excinfo.value.packet_number == 1
    assert excinfo.value.file_path == TEST_FILE_PATH
