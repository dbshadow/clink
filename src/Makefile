EXEC=clink
SRC=clink.c exec_ev.c

LDFLAGS += -lsutil -luci

all: $(EXEC)

$(EXEC): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -lev -o $@ $(SRC)

clean:
	-rm -f $(EXEC) *.o
