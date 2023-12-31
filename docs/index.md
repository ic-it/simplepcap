# Simple PCAP file parser

![SimplePCAP. Logo Author: @mellin_venera](./assets/images/minilogo.png)  
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
    ![PyPI](https://img.shields.io/pypi/v/simplepcap)
](https://pypi.org/project/simplepcap/)

> Based on [this](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html) 
> and [this](https://wiki.wireshark.org/Development/LibpcapFileFormat#global-header) 
> PCAP Capture File Format description.

## About
Simple PCAP was created to allow the user to focus as much as possible on processing packets stored in 
a pcap file without studying its structure. This is a very simple tool, it does not provide additional 
tools for analyzing packages. The library tries to provide the safest possible manipulation of pcap files.


## Installation
### From PyPI
```bash
pip install simplepcap
```

### From GitHub
```bash
pip install git+https://github.com/ic-it/simplepcap.git
```

## Usage
Look at the [examples](examples.md) folder.

## Documentation
Look at the [docs](https://ic-it.github.io/simplepcap/).


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
