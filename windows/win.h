#ifndef HTTP_PROXY_WIN_H_
#define HTTP_PROXY_WIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <time.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <MSWSock.h>

#ifdef __cplusplus
extern "C" {
#endif

#undef errno
#define errno WSAGetLastError()
#define close(fd) closesocket(fd)
#define strerror(errcode) win_strerror(errcode)
#define strcasecmp _stricmp

extern void win_init();

extern void win_uninit();

const char* win_strerror(int err_code);

const char* win_get_exe_path();

#ifdef __cplusplus
}
#endif

#endif