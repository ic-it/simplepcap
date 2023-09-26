from pprint import pprint
from simplepcap.parsers import DefaultParser
from simplepcap.types import Packet


def filter_func(packet: Packet):
    return len(packet.data) < 100


with DefaultParser(file_path="./pcaps/eth-1.pcap") as parser:
    pprint(parser.file_header)
    for packet in filter(filter_func, parser):
        pprint(packet)
