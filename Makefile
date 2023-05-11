all:
	mkdir -p bin
	clang simple_pcap_parser.c -Wall -Wpedantic -Wextra -Ofast -o ./bin/parse_pcap
	./bin/parse_pcap ./net.cap ./output.jpg
