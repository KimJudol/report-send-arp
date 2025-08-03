LDLIBS += -lpcap

all: report-send-arp

report-send-arp: report-send-arp.o
	g++ -o report-send-arp report-send-arp.o -lpcap

report-send-arp.o: arp_hdr.h eth_hdr.h report-send-arp.cpp
	g++ -c -o report-send-arp.o report-send-arp.cpp

clean:
	rm -f report-send-arp *.o