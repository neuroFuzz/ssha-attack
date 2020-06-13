CFLAGS = -O3
LIBS = -lssl -lcrypto
OBJS = functions.o ssha_attack.o

all: $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o ssha_attack

ssha_attack.o: ssha_attack.c
	$(CC) $(CFLAGS) -c -o $@ $<
functions.o: functions.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f ssha_attack *.o


