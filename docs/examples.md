# Examples

## Basic usage

```python
from simplepcap.parsers import DefaultParser


with DefaultParser(file_path="./pcaps/eth-1.pcap") as parser:
    print(parser.file_header)
    for packet in parser:
        print(packet)

```

## Filtering

```python
from simplepcap import Packet
from simplepcap.parsers import DefaultParser


def filter_func(packet: Packet):
    return len(packet.data) < 100


with DefaultParser(file_path="./pcaps/eth-1.pcap") as parser:
    print(parser.file_header)
    for packet in filter(filter_func, parser):
        print(packet)

```