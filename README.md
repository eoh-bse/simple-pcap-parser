# Simple Pcap file parser
Parser that parses a pcap file and stores the contents in the output file from packets for a single HTTP/1.1 request/response

## Limitations
* Implementation assumes `little endianness`
* Implementation can only parse raw data and does not handle any special encoding such as `gzip`
* Implementation assumes the pcap file contains packets for a single HTTP/1.1 request/response 
