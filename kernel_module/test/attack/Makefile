CC	= gcc
CFLAGS	= -Wall -g -MD -O0 -I ../

all: attack 

attack: attack.o
	$(CC) $(CFLAGS) $(<) -o attack

clean:
	rm -f *.o attack *.d

-include *.d
