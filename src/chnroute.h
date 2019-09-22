#ifndef HTTP_PROXY_CHNROUTE_H_
#define HTTP_PROXY_CHNROUTE_H_

#include <stdint.h>
#ifdef WINDOWS
#include "../windows/win.h"
#else
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

int chnroute_init();

void chnroute_free();

int chnroute_test4(struct in_addr* ip);

int chnroute_test6(struct in6_addr* ip);

int chnroute_test(struct sockaddr* addr);

int chnroute_parse(const char* filename);

#ifdef __cplusplus
}
#endif

#endif
