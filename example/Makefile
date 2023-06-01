
CC     = gcc
CFLAGS = -O2
LIBS   = -lssl -lcrypto
RM     = rm

ALL    = dtls_client dtls_server

#------------------------------------------------------------------------------

all: $(ALL)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	$(RM) $(ALL)
