debug = 0

OBJS = src/base64url.o \
       src/log.o \
       src/stream.o \
       src/chnroute.o \
       src/dnscache.o \
       src/domain_dic.o \
       http-parser/http_parser.o \
       rbtree/rbtree.c

CFLAGS += -DASYN_DNS
MY_LIBS += -lcares

ifneq ($(debug), 0)
    CFLAGS += -g -DDEBUG -D_DEBUG
    LDFLAGS += -g
endif

all: http-proxy

http-proxy: src/main.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(MY_LIBS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean
clean:
	-rm -f src/*.o http-proxy


