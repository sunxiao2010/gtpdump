CFLAGS = -O0 -ggdb -g3 -DGTPDUMP_DEBUG
CXXFLAGS = -O0 -ggdb -g3 -DGTPDUMP_DEBUG
LINK=-lpcap -lstdc++ 

all:gtp.o gtp_session.o main.o opt.o
	$(CC) gtp.o gtp_session.o opt.o main.o -o gtpdump $(CFLAGS) $(LINK)
gtp.o:gtp.c
	$(CC) -c gtp.c -o gtp.o $(CFLAGS)
gtp_session.o:gtp_session.cpp
	$(CXX) -c gtp_session.cpp -o gtp_session.o $(CXXFLAGS) -Wno-deprecated
opt.o:getopt.c
	$(CC) -c getopt.c -o opt.o $(CFLAGS)
main.o:main.c
	$(CC) -c main.c -o main.o $(CFLAGS)
clean:
	rm -f *.o core-* gtpdump dump.pcap
