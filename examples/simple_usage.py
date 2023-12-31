from pprint import pprint
from simplepcap.parsers import DefaultParser


with DefaultParser(file_path="./pcaps/eth-1.pcap") as parser:
    pprint(parser.file_header)
    for packet in parser:
        pprint(packet)
