all : send_arp

send_arp: main.o
	g++ -g -o arp_spoof main.o -lpcap

main.o:
	g++ -g -c -o main.o main.c

clean:
	rm -f arp_spoof
	rm -f *.o

