debug = 0

GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || true)

ifneq ("$(GIT_HASH)", "")
    GIT_DIRTY := $(shell git diff --stat 2>/dev/null || true)
    ifneq ("$(GIT_DIRTY)", "")
        GIT_VERSION = $(GIT_HASH)-dirty
    else
        GIT_VERSION = $(GIT_HASH)
    endif
endif

OBJS = src/base64url.o \
       src/log.o \
       src/stream.o \
       src/chnroute.o \
       src/dnscache.o \
       src/domain_dic.o \
       http-parser/http_parser.o \
       rbtree/rbtree.c

CFLAGS += $(MFLAGS) -DASYN_DNS
MY_LIBS += -lcares

ifneq ($(debug), 0)
    CFLAGS += -g -ggdb -DDEBUG -D_DEBUG
    LDFLAGS += -g -ggdb
endif

all: http-proxy

http-proxy: src/main.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) $(MY_LIBS)

src/main.o: src/main.c
	@cat src/build_version.h.in | sed "s/\$$GIT_VERSION/$(GIT_VERSION)/g" > src/build_version.h
	@echo GIT_VERSION=$(GIT_VERSION)
	$(CC) -o $@ -c $< $(CFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY : install
install:
	-rm /usr/local/bin/http-proxy
	cp ./http-proxy /usr/local/bin

.PHONY : uninstall
uninstall:
	rm /usr/local/bin/http-proxy

.PHONY: clean
clean:
	-rm -f http-parser/*.o rbtree/*.o src/*.o http-proxy


