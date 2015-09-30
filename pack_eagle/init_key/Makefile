SRCS:=main.c sm3.c sms4.c 

CFLAGS:= -O2 -Wall -Wno-unused-parameter
LIBS:=-lwng4
LDFLAGS:=-L.

TOOLCHAIN=/opt/arm-none-linux-toolchain/bin/arm-none-linux-gnueabi-
CC= $(TOOLCHAIN)gcc

OBJS= $(SRCS:.c=.o)

all:init_key

init_key:$(OBJS) libwng4.so
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

libwng4.so:
	$(CC) -shared -o $@ $(LDFLAGS) random_WNG4.c

clean:
	rm *.o init_key *.so
