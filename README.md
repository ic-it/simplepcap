# Simple PCAP file parser

![SimplePCAP. Logo Author: @mellin_venera](./docs/assets/images/minilogo.png)  
[
    ![lint](https://img.shields.io/github/actions/workflow/status/ic-it/simplepcap/lint.yml)
](https://github.com/ic-it/simplepcap/actions)
[
    ![IC-IT](https://img.shields.io/badge/IC--IT-2023-blue)
](https://github.com/ic-it/)
[
    ![License](https://img.shields.io/github/license/ic-it/simplepcap)
](
    https://github.com/ic-it/simplepcap/blob/main/LICENSE
)
[
    ![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)
](
    https://www.python.org/downloads/release/python-3100/
)
[
    ![Documentation Status](https://img.shields.io/badge/docs-latest-brightgreen.svg?style=flat)
](https://ic-it.github.io/simplepcap/)
[
    ![Version](https://img.shields.io/badge/version-0.1.7-blue)
](https://github.com/ic-it/simplepcap)

> Based on [this](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html) 
> and [this](https://wiki.wireshark.org/Development/LibpcapFileFormat#global-header) 
> PCAP Capture File Format description.

## About
Simple PCAP was created to allow the user to focus as much as possible on processing packets stored in 
a pcap file without studying its structure. This is a very simple tool, it does not provide additional 
tools for analyzing packages. The library tries to provide the safest possible manipulation of pcap files.


## Installation
```bash
pip install git+https://github.com/ic-it/simplepcap.git
```

## Usage example
### Simple usage
```python
from pprint import pprint
from simplepcap.parsers import DefaultParser


with DefaultParser(file_path="./pcaps/eth-1.pcap") as parser:
    pprint(parser.file_header)
    for packet in parser:
        pprint(packet)
```

### Get all packets
```python
from pprint import pprint
from simplepcap.parsers import DefaultParser


with DefaultParser(file_path="./pcaps/eth-1.pcap") as parser:
    packets = list(parser) # or packets = parser.get_all_packets()

pprint(packets)
```

Look at the [examples](./examples) folder for more examples.

## Documentation
Look at the [docs](https://ic-it.github.io/simplepcap/).


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
