flood:
	gcc synflood.c -o flood.out -lpcap

server:
	gcc minimal_tcp_server.c -o server.out

clean:
	rm -rf *.out