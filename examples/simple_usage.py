from simplepcap.parsers import DefaultParser


with DefaultParser(file_path="./pcaps/eth-1.pcap") as parser:
    print(parser.file_header)
