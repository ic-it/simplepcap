# Simple PCAP file parser

![SimplePCAP. Logo Author: @mellin_venera](./assets/images/minilogo.png)  
[
    ![lint](https://img.shields.io/github/actions/workflow/status/ic-it/simplepcap/lint.yml)
](https://github.com/ic-it/simplepcap/actions)
[
    ![IC-IT](https://img.shields.io/badge/IC--IT-2023-blue)
](https://github.com/ic-it/)
[
    ![Documentation Status](https://img.shields.io/badge/docs-latest-brightgreen.svg?style=flat)
](https://ic-it.github.io/simplepcap/)
[
    ![Version](https://img.shields.io/badge/version-0.1.0--alpha-blue)
](https://github.com/ic-it/simplepcap)
<!-- [
    ![PyPI version](https://badge.fury.io/py/simplepcap.svg)
](https://badge.fury.io/py/simplepcap) -->

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

## Usage
Look at the [examples](examples.md) folder.

## Documentation
Look at the [docs](https://ic-it.github.io/simplepcap/).


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
