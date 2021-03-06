#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>

#ifdef WINDOWS

#include "../windows/win.h"
typedef SOCKET sock_t;

#ifdef ASYN_DNS

/* c-ares (https://c-ares.haxx.se/).
   Can build from c-ares source,
   ref https://github.com/c-ares/c-ares/blob/master/INSTALL.md#msvc-from-command-line. */

#ifdef WIN64

#include "../windows/c-ares/x64/include/ares.h"
#pragma comment(lib,"../windows/c-ares/x64/lib/cares.lib")

#else /* else WIN64 */

#include "../windows/c-ares/x86/include/ares.h"
#pragma comment(lib,"../windows/c-ares/x86/lib/cares.lib")

#endif /* endif WIN64 */

#endif /* endif ASYN_DNS */

#else /* else WINDOWS */

#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <syslog.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>

#ifdef ASYN_DNS
#include <ares.h>
#endif

typedef int sock_t;
#define strnicmp strncasecmp

#endif  /* endif WINDOWS */


#include "log.h"
#include "dllist.h"
#include "stream.h"
#include "../http-parser/http_parser.h"
#include "chnroute.h"
#include "dnscache.h"
#include "base64url.h"
#include "domain_dic.h"
#include "version.h"

#define DEFAULT_LISTEN_ADDR "0.0.0.0"
#define DEFAULT_LISTEN_PORT "1080"
#define DEFAULT_PID_FILE "/var/run/http-proxy.pid"
#define DEFAULT_TIMEOUT 30
#define DEFAULT_DNS_TIMEOUT 600 /* 10 minutes */
#define LISTEN_BACKLOG	128
#ifndef MAX_LISTEN
#define MAX_LISTEN 8
#endif
#ifndef BUF_SIZE
#define BUF_SIZE 4096
#endif
#ifndef MAX_HEADER_SIZE
#define MAX_HEADER_SIZE (1 * 1024 * 1024) /* 1 MiB */
#endif
#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE (2 * 1024 * 1024) /* 2 MiB */
#endif
#ifndef MAX_PROXY
#define MAX_PROXY 8
#endif

#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#define _XSTR(x) #x  
#define XSTR(x) _XSTR(x)

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef EINPROGRESS
#define EINPROGRESS EAGAIN
#endif

#ifndef WSAEWOULDBLOCK
#define WSAEWOULDBLOCK EINPROGRESS
#endif

#ifndef WSAETIMEDOUT
#define WSAETIMEDOUT ETIMEDOUT
#endif

#ifndef EAI_NODATA
#define EAI_NODATA EAI_NONAME
#endif

#ifndef EAI_ADDRFAMILY
#define EAI_ADDRFAMILY EAI_NODATA
#endif

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE SO_REUSEADDR
#endif

#define ERR_CREATE_SOCKET -1
#define ERR_SET_NONBLOCK  -2
#define ERR_CONNECT		  -3

/* Proxy type */
#define SOCKS5_PROXY 0
#define HTTP_PROXY   1

#define PROXY_USERNAME_LEN 50
#define PROXY_PASSWORD_LEN 50

#ifndef MIN
#define MIN(a, b) ((a) > (b) ? (b) : (a))
#endif

#define is_eagain(err) ((err) == EAGAIN || (err) == EINPROGRESS || (err) == EWOULDBLOCK || (err) == WSAEWOULDBLOCK)

#define is_true_val(s) \
	(strcmp((s), "1") == 0 || \
	strcmp((s), "on") == 0 || \
	strcmp((s), "true") == 0 || \
	strcmp((s), "yes") == 0 || \
	strcmp((s), "enabled") == 0)

typedef struct sockaddr_t sockaddr_t;
typedef struct conn_t conn_t;

typedef void (*got_addr_callback)(sockaddr_t* addr, int hit_cache, conn_t* conn,
	const char* host, const char* port);

#ifdef ASYN_DNS
typedef struct a_state_t {
	sockaddr_t* addr;
	char* host;
	char* port;
	conn_t* conn;
	got_addr_callback cb;
	int af_inet; /* Is IPv4 address queryed? */
	int af_inet6; /* Is IPv6 address queryed? */
	int cur_family;
	int is_conn_destroyed;
} a_state_t;
#endif

typedef struct ip_t {
	int family; /* AF_INET or AF_INET6 */
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} ip;
} ip_t;

struct sockaddr_t {
	struct sockaddr_storage addr;
	socklen_t addrlen;
};

typedef struct proxy_t {
	int proxy_type;
	sockaddr_t addr;
	int proxy_index;
	char username[PROXY_USERNAME_LEN];
	char password[PROXY_PASSWORD_LEN];
	int is_support_ipv4;
	int is_support_ipv6;
} proxy_t;

typedef struct listen_t {
	sockaddr_t addr;
	sock_t sock;
} listen_t;

typedef enum field_status {
	fs_none = 0,
	fs_name,
	fs_value,
} field_status;

typedef enum conn_status {
	cs_none = 0,
	cs_connecting,
	cs_connected,
	cs_closing, /* close immediately */
	cs_rsp_closing, /* close after response */
} conn_status;

typedef enum proxy_mode {
	pm_none = 0,
	pm_proxy,
	pm_tunnel,
} proxy_mode;

typedef enum proxy_status {
	ps_none = 0,
	ps_handshake0,
	ps_handshake1,
} proxy_status;

typedef struct proxy_ctx {
	proxy_status status;
	stream_t rs; /* read stream */
	stream_t ws; /* write stream */
} proxy_ctx;

struct conn_t {
	listen_t* listen;
	sock_t sock;
	sock_t rsock; /* remote sock */
	sockaddr_t raddr; /* remote address */
	proxy_mode mode;
	conn_status status;
	stream_t ws; /* write stream */
	stream_t rws; /* remote write stream */
	dlitem_t entry;
	http_parser parser;
	time_t expire;
	size_t header_size;
	stream_t url;
	char* host; /* host from HTTP request header */
	char* rhost; /* domain name */
	char* rport; /* port name*/
	int is_first_line;
	struct {
		stream_t name;
		stream_t value;
		field_status status;
	} field;
	int by_proxy;
	int by_pass;
	int proxy_index;
	proxy_ctx* proxy;
	uint64_t rx; /* receive bytes */
	uint64_t tx; /* transmit bytes */
	uint64_t rrx; /* remote receive bytes */
	uint64_t rtx; /* remote transmit bytes */
#ifdef ASYN_DNS
	a_state_t* a_state;
#endif
	unsigned long tm_start;
	int is_first_response;
	int is_remote_connected;
};

static char* listen_addr = NULL;
static char* listen_port = NULL;
static char* pid_file = NULL;
static char* log_file = NULL;
static int daemonize = 0;
static char* launch_log = NULL;
static char* config_file = NULL;
static int timeout = 0;
static char* proxy = NULL;
static char* chnroute = NULL;
static int ipv6_prefer = 0;
static int dns_timeout = -1;
static char* forbidden_file = NULL;
static int reverse = 0;
static int resolve_on_server = 0;
static char *domain_file = NULL;
static int fallback_no_proxy = -2; /* TRUE|FALSE, -2 mean do not set */

static int running = 0;
static listen_t listens[MAX_LISTEN] = { 0 };
static int listen_num = 0;
static dllist_t conns = DLLIST_INIT(conns);
static proxy_t proxy_list[MAX_PROXY] = { 0 };
static int proxy_num = 0;
static chnroute_ctx chnr = NULL;
static chnroute_ctx forb = NULL;
static ip_t* local_ips = NULL;
static int local_ip_cnt = 0;
static domain_dic_t domains = { 0 };

#ifdef WINDOWS

static SERVICE_STATUS ServiceStatus = { 0 };
static SERVICE_STATUS_HANDLE hStatus = NULL;

static void ServiceMain(int argc, char** argv);
static void ControlHandler(DWORD request);
#define strdup(s) _strdup(s)

#endif

#ifdef ASYN_DNS
static char* dns_server = NULL;
static ares_channel a_channel = NULL;
static struct ares_options a_options = { 0 };
#endif

#define get_addrport(a) \
	((a)->addr.ss_family == AF_INET ? \
		((struct sockaddr_in*)(&((a)->addr)))->sin_port :\
		((struct sockaddr_in6*)(&((a)->addr)))->sin6_port)

#define get_proxyinfo(index) \
	(proxy_list + (index))

#define get_proxyname(index) \
	get_sockaddrname(&get_proxyinfo(index)->addr)

#define get_conn_proxyname(conn) \
	get_sockaddrname(&get_proxyinfo((conn)->proxy_index)->addr)

static int handle_write(conn_t* conn);
static int handle_recv(conn_t* conn);
static int handle_rwrite(conn_t* conn);
static int handle_rrecv(conn_t* conn);
static int connect_proxy(int proxy_index, conn_t* conn);
static int proxy_handshake(conn_t* conn);
static int proxy_recv(conn_t* conn);
static int proxy_write(conn_t* conn);

static char* ltrim(char* s)
{
	char* p = s;
	while (p && (*p) && isspace((int)(*((unsigned char*)p))))
		p++;
	return p;
}

char* rtrim(char* s)
{
	size_t len;
	char* p;

	len = strlen(s);
	p = s + len - 1;

	while (p >= s && isspace((int)(*((unsigned char*)p)))) (*(p--)) = '\0';

	return s;
}

static char* trim_quote(char* s)
{
	char* start, * end;
	size_t len;

	len = strlen(s);
	start = s;
	end = s + len - 1;

	while ((*start) && ((*start) == '\'' || (*start) == '"'))
		start++;

	while (end >= start && ((*end) == '\'' || (*end) == '"')) (*(end--)) = '\0';

	return start;
}

/* case insensitive */
static int startwith(const char* s, const char* needle)
{
	int i, len;

	if (!s || !needle)
		return FALSE;

	len = (int)strlen(needle);
	for (i = 0; i < len; i++) {
		if (!s[i] || toupper(s[i]) != toupper(needle[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

static unsigned long OS_GetTickCount()
{
#ifdef WINDOWS
	return clock();
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
}

#ifdef ASYN_DNS

static int init_ares()
{
	int rc, optmask = 0;

	rc = ares_library_init(ARES_LIB_INIT_ALL);
	if (rc != ARES_SUCCESS) {
		loge("ares_library_init: %s\n", ares_strerror(rc));
		return -1;
	}

	rc = ares_init_options(&a_channel, &a_options, optmask);
	if (rc != ARES_SUCCESS) {
		loge("ares_init_options: %s\n", ares_strerror(rc));
		return -1;
	}

	if (dns_server) {
		rc = ares_set_servers_ports_csv(a_channel, dns_server);
		if (rc != ARES_SUCCESS) {
			loge("ares_set_servers_ports_csv: %s\n", ares_strerror(rc));
			return -1;
		}
	}

	return 0;
}

static void free_ares()
{
	ares_destroy(a_channel);
	ares_library_cleanup();
}

static void a_print_servers()
{
	int r;
	struct ares_addr_port_node* nodes = NULL, *n;
	char ip[INET6_ADDRSTRLEN];
	int idx = 0;

	logn("c-ares dns servers (c-ares v%s):\n", ares_version(NULL));
	r = ares_get_servers_ports(a_channel, &nodes);
	if (nodes && r == ARES_SUCCESS) {
		n = nodes;
		while (n) {
			inet_ntop(n->family, &n->addr, ip, sizeof(ip));
			logn("  %d. %s:udp%d,tcp%d\n",
				++idx,
				ip,
				n->udp_port ? n->udp_port : 53,
				n->tcp_port ? n->tcp_port : 53);
			n = n->next;
		}
	}
	if (nodes)
		ares_free_data(nodes);
}

static a_state_t* a_new_state(sockaddr_t* addr, char* host, char* port,
	conn_t* conn, got_addr_callback cb)
{
	a_state_t* st = (a_state_t*)malloc(sizeof(a_state_t));
	if (!st)
		return NULL;
	memset(st, 0, sizeof(a_state_t));
	st->addr = addr;
	st->host = strdup(host);
	st->port = strdup(port);
	st->conn = conn;
	st->cb = cb;
	conn->a_state = st;
	logv("a_new_state()\n");
	return st;
}

static void a_free_state(a_state_t* st)
{
	if (st) {
		if (st->conn) {
			st->conn->a_state = NULL;
		}
		free(st->host);
		free(st->port);
		free(st);
		logv("a_free_state()\n");
	}
}

static void a_get_addr_st(a_state_t* st, int family);

static void a_callback(void* arg, int status, int timeouts, struct hostent* host)
{
	a_state_t* st = (a_state_t*)arg;
	char ip[INET6_ADDRSTRLEN];
	int i = 0;
	sockaddr_t* addr = NULL;
	struct sockaddr_in* addr_in;
	struct sockaddr_in6* addr_in6;
	struct in_addr* in;
	struct in6_addr* in6;

	if (host && status == ARES_SUCCESS) {
		stream_t s = STREAM_INIT();
		if (loglevel >= LOG_DEBUG) {
			stream_writef(&s, "a_callback() %s records for %s: ",
				st->cur_family == AF_INET ? "A" : "AAAA",
				host->h_name);
		}
		for (i = 0; host->h_addr_list[i]; ++i) {
			if (loglevel >= LOG_DEBUG) {
				stream_appendf(
					&s,
					"%s%s",
					i > 0 ? "," : "",
					inet_ntop(
						host->h_addrtype,
						host->h_addr_list[i],
						ip,
						sizeof(ip)));
			}
			if (!addr) {
				switch (host->h_addrtype) {
				case AF_INET:
					addr = st->addr;
					in = (struct in_addr*)host->h_addr_list[i];
					addr_in = (struct sockaddr_in*)(&addr->addr);
					addr->addrlen = sizeof(struct sockaddr_in);
					addr_in->sin_family = AF_INET;
					addr_in->sin_port = htons(atoi(st->port));
					memcpy(&addr_in->sin_addr, in, sizeof(struct in_addr));
					break;
				case AF_INET6:
					addr = st->addr;
					in6 = (struct in6_addr*)host->h_addr_list[i];
					addr_in6 = (struct sockaddr_in6*)(&addr->addr);
					addr->addrlen = sizeof(struct sockaddr_in6);
					addr_in6->sin6_family = AF_INET6;
					addr_in6->sin6_port = htons(atoi(st->port));
					memcpy(&addr_in6->sin6_addr, in6, sizeof(struct in6_addr));
					break;
				}
			}
		}
		if (loglevel >= LOG_DEBUG) {
			logd("%s\n", s.array);
			stream_free(&s);
		}
	}

	if (!addr) {
		loge("a_callback(): failed to lookup %s record for %s (repeat %d times): %s\n",
			st->cur_family == AF_INET ? "A" : "AAAA",
			st->host,
			timeouts,
			ares_strerror(status));
		if (!st->af_inet6)
			a_get_addr_st(st, AF_INET6);
		else if (!st->af_inet)
			a_get_addr_st(st, AF_INET);
		else {
			if (!st->is_conn_destroyed && st->conn) {
				(*st->cb)(NULL, FALSE, st->conn, st->host, st->port);
			}
			a_free_state(st);
		}
		return;
	}
	else {
		if (dns_timeout > 0) {
			if (dnscache_set(st->host, (char*)addr, sizeof(sockaddr_t))) {
				logw("a_callback() error: set dns cache failed - %s\n", st->host);
			}
		}
		if (!st->is_conn_destroyed && st->conn) {
			(*st->cb)(addr, FALSE, st->conn, st->host, st->port);
		}
		a_free_state(st);
		return;
	}
}

static void a_get_addr_st(a_state_t *st, int family)
{
	st->af_inet = st->af_inet || family == AF_INET;
	st->af_inet6 = st->af_inet6 || family == AF_INET6;
	st->cur_family = family;
	
	ares_gethostbyname(a_channel, st->host, family, a_callback, st);
}

static int a_get_addr(sockaddr_t* addr, char *host, char *port,
	conn_t* conn, got_addr_callback cb)
{
	a_state_t* st = a_new_state(addr, host, port, conn, cb);
	if (!st) {
		loge("a_get_addr() failed: a_new_state() failed: alloc");
		return -1;
	}

	a_get_addr_st(st, ipv6_prefer ? AF_INET6 : AF_INET);

	return 0;
}

#endif

static int is_same_ip(ip_t *ip, struct sockaddr* addr)
{
	if (ip->family == addr->sa_family) {
		if (ip->family == AF_INET) {
			return memcmp(
				&ip->ip.ip4,
				&((struct sockaddr_in*)addr)->sin_addr,
				4) == 0;
		}
		else if (ip->family == AF_INET6) {
			return memcmp(
				&ip->ip.ip4,
				&((struct sockaddr_in6*)addr)->sin6_addr,
				16) == 0;
		}
	}

	return FALSE;
}

static int is_same_ip2(struct sockaddr* addr1, struct sockaddr* addr2)
{
	if (addr1->sa_family == addr2->sa_family) {
		if (addr1->sa_family == AF_INET) {
			return memcmp(
				&((struct sockaddr_in*)addr1)->sin_addr,
				&((struct sockaddr_in*)addr2)->sin_addr,
				4) == 0;
		}
		else if (addr1->sa_family == AF_INET6) {
			return memcmp(
				&((struct sockaddr_in6*)addr1)->sin6_addr,
				&((struct sockaddr_in6*)addr2)->sin6_addr,
				16) == 0;
		}
	}

	return FALSE;
}

static int is_any_addr(struct sockaddr* addr)
{
	ip_t any = {
		.family = addr->sa_family
	};
	return is_same_ip(&any, addr);
}

static int is_local_ip(struct sockaddr* target_addr)
{
	int i;

	if (local_ip_cnt == 0)
		return FALSE;

	for (i = 0; i < local_ip_cnt; i++) {
		if (is_same_ip(local_ips + i, target_addr))
			return TRUE;
	}

	return FALSE;
}

static int is_self(sockaddr_t* addr)
{
	int i, num = listen_num;
	listen_t* listen;
	struct sockaddr* listen_addr;
	struct sockaddr* target_addr = (struct sockaddr*) & addr->addr;

	for (i = 0; i < num; i++) {
		listen = listens + i;
		if (listen->addr.addr.ss_family == addr->addr.ss_family &&
			get_addrport(&(listen->addr)) == get_addrport(addr)) {
			
			listen_addr = (struct sockaddr*) & listen->addr.addr;
			
			if (is_any_addr(listen_addr)) {
				if (is_local_ip(target_addr))
					return TRUE;
			}
			else {
				if (is_same_ip2(listen_addr, target_addr))
					return TRUE;
			}

		}
	}

	return FALSE;
}

static int is_forbidden(sockaddr_t *addr)
{
	struct sockaddr* saddr = (struct sockaddr*) & addr->addr;

	if (is_self(addr))
		return TRUE;

	if (forb) {
		if (chnroute_test(forb, saddr))
			return TRUE;
	}

	return FALSE;
}

static int setnonblock(sock_t sock)
{
#ifdef WINDOWS
	int iResult;
	/* If iMode!=0, non-blocking mode is enabled.*/
	u_long iMode = 1;
	iResult = ioctlsocket(sock, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		loge("ioctlsocket() error: result=%ld, errno=%d, %s\n",
			iResult, errno, strerror(errno));
		return -1;
	}
#else
	int flags;
	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) {
		loge("fcntl() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		loge("fcntl() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}
#endif

	return 0;
}

static int setreuseaddr(sock_t sock)
{
	int opt = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &opt, sizeof(opt)) != 0) {
		loge("setsockopt() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int setnodelay(sock_t sock)
{
	int opt = 1;

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) != 0) {
		loge("setsockopt() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int getsockerr(sock_t sock)
{
	int err = 0;
	socklen_t len = sizeof(socklen_t);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len) < 0)
		return errno;
	return err;
}

static char* get_ipname(int family, void* addr)
{
	static char sip[INET6_ADDRSTRLEN];
	inet_ntop(family, addr, sip, sizeof(sip));
	return sip;
}

static char* get_addrname(struct sockaddr* addr)
{
	static char addrname[INET6_ADDRSTRLEN + 16];
	char sip[INET6_ADDRSTRLEN];
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
		inet_ntop(AF_INET, &addr_in->sin_addr, sip, sizeof(sip));
		snprintf(addrname, sizeof(addrname), "%s:%d", sip,
			(int)(htons(addr_in->sin_port) & 0xFFFF));
	}
	else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;
		inet_ntop(AF_INET6, &addr_in6->sin6_addr, sip, sizeof(sip));
		snprintf(addrname, sizeof(addrname), "[%s]:%d", sip,
			(int)(htons(addr_in6->sin6_port) & 0xFFFF));
	}
	else {
		addrname[0] = '\0';
	}
	return addrname;
}

static char* get_sockaddrname(sockaddr_t* addr)
{
	return get_addrname((struct sockaddr*)(&addr->addr));
}

/* get remote address name */
static char* get_sockname(sock_t sock)
{
	static char buffer[INET6_ADDRSTRLEN + 16] = { 0 };
	char sip[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);
	int err = getpeername(sock, (struct sockaddr*) & addr, &len);
	if (err != 0)
		return NULL;
	if (addr.ss_family == AF_INET) {
		struct sockaddr_in* s = (struct sockaddr_in*) & addr;
		inet_ntop(AF_INET, &s->sin_addr, sip, sizeof(sip));
		snprintf(buffer, sizeof(buffer), "%s:%d", sip,
			(int)(htons(s->sin_port) & 0xFFFF));
		return buffer;
	}
	else if (addr.ss_family == AF_INET6) {
		struct sockaddr_in6* s = (struct sockaddr_in6*) & addr;
		inet_ntop(AF_INET6, &s->sin6_addr, sip, sizeof(sip));
		snprintf(buffer, sizeof(buffer), "[%s]:%d", sip,
			(int)(htons(s->sin6_port) & 0xFFFF));
		return buffer;
	}
	return NULL;
}

static void print_local_ips(ip_t* list, int cnt)
{
	char* name;
	int i;

	if (cnt == 0)
		return;

	logd("local ip list: \n");
	for (i = 0; i < cnt; i++) {
		name = get_ipname(list[i].family, &list[i].ip);
		logd("  %d. %s\n", i + 1, name);
	}
}

#ifdef WINDOWS

static int get_all_ips_by_name(ip_t** list, const char *host_name)
{
	struct addrinfo hints;
	struct addrinfo* addrinfo, * p;
	ip_t* ip;
	int r;

	memset(&hints, 0, sizeof(hints));

	r = getaddrinfo(host_name, 0, &hints, &addrinfo);

	if (r != 0)
	{
		loge("get_all_ips_by_name() error: retval=%d %s %s\n",
			r, gai_strerror(r), host_name);
		return -1;
	}

	p = addrinfo;
	r = 0;

	while (p) {
		r++;
		p = p->ai_next;
	}

	ip = (ip_t*)malloc(sizeof(ip_t) * r);
	if (!ip) {
		loge("get_all_ips_by_name() error: alloc\n");
		freeaddrinfo(addrinfo);
		return -1;
	}

	*list = ip;

	memset(ip, 0, sizeof(ip_t) * r);

	p = addrinfo;

	r = 0;
	while (p) {

		ip->family = p->ai_addr->sa_family;
		if (ip->family == AF_INET) {
			memcpy(&ip->ip.ip4,
				&((struct sockaddr_in*)p->ai_addr)->sin_addr, 4);
			r++;
			ip++;
		}
		else if (ip->family == AF_INET6) {
			memcpy(&ip->ip.ip6,
				&((struct sockaddr_in6*)p->ai_addr)->sin6_addr, 16);
			r++;
			ip++;
		}

		p = p->ai_next;
	}

	freeaddrinfo(addrinfo);

	return r;
}

static int get_lo_ips(ip_t** list)
{
	return get_all_ips_by_name(list, "localhost");
}

static int get_if_ips(ip_t** list)
{
	char host_name[255];

	if (gethostname(host_name, sizeof(host_name))) {
		loge("get_if_ips(): failed to get host name: errno=%d, %s\n",
			errno, strerror(errno));
		return -1;
	}

#ifdef _DEBUG
	logd("host name: %s\n", host_name);
#endif

	return get_all_ips_by_name(list, host_name);
}

static int combin_iplist(ip_t** all,
	ip_t *list0, int list0_cnt,
	ip_t *list1, int list1_cnt)
{
	int cnt = list0_cnt + list1_cnt;
	ip_t *list = (ip_t*)malloc(sizeof(ip_t) * cnt);

	if (!list) {
		loge("combin_iplist(): alloc\n");
		return -1;
	}

	memcpy(list, list0, sizeof(ip_t) * list0_cnt);
	memcpy(list + list0_cnt, list1, sizeof(ip_t) * list1_cnt);

	*all = list;

	return cnt;
}

static int iplist_exists(ip_t* list, int cnt, ip_t *ip)
{
	int i, sz;
	ip_t* p;

	for (i = 0; i < cnt; i++) {
		p = list + i;
		if (p->family == ip->family) {
			if (p->family == AF_INET)
				sz = 4;
			else if (p->family == AF_INET6)
				sz = 16;
			else
				return TRUE;
			if (memcmp(&p->ip, &ip->ip, sz) == 0)
				return TRUE;
		}
	}

	return FALSE;
}

static int iplist_rm_dup(ip_t *list, int cnt)
{
	int i, n = 0;

	for (i = 0; i < cnt; i++) {
		if (!iplist_exists(list, n, list + i)) {
			if (n != i) {
				memcpy(list + n, list + i, sizeof(ip_t));
			}
			n++;
		}
	}

	return n;
}

static int get_local_ips(ip_t** list)
{
	ip_t* localhost_ips = NULL, *if_ips = NULL;
	int localhost_ip_cnt = 0, if_ips_cnt = 0, cnt = 0;

	localhost_ip_cnt = get_lo_ips(&localhost_ips);

	if (localhost_ip_cnt < 0) {
		return -1;
	}

	if_ips_cnt = get_if_ips(&if_ips);

	if (if_ips_cnt < 0) {
		free(localhost_ips);
		return -1;
	}
	
	cnt = combin_iplist(list,
		localhost_ips, localhost_ip_cnt,
		if_ips, if_ips_cnt);

	free(localhost_ips);
	free(if_ips);

	if (cnt < 0) {
		return -1;
	}

	cnt = iplist_rm_dup(*list, cnt);

	return cnt;
}

#else /* else WINDOWS */

static int get_local_ips(ip_t** list)
{
	struct ifaddrs* myaddrs, * ifa;
	ip_t* ip;
	int cnt, family;
	void* in_addr;
	char buf[64];

	if (getifaddrs(&myaddrs) != 0)
	{
		loge("get_local_ips() error: errno=%d %s\n",
			errno, strerror(errno));
		return -1;
	}

	cnt = 0;
	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		family = ifa->ifa_addr->sa_family;
		if (family != AF_INET && family != AF_INET6)
			continue;
		cnt++;
	}

	ip = (ip_t*)malloc(sizeof(ip_t) * cnt);
	if (!ip) {
		loge("get_local_ips() error: alloc\n");
		freeifaddrs(myaddrs);
		return -1;
	}

	*list = ip;

	memset(ip, 0, sizeof(ip_t) * cnt);

	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		family = ifa->ifa_addr->sa_family;
		switch (family) {
		case AF_INET:
			in_addr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
			break;
		case AF_INET6:
			in_addr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
			break;
		default:
			continue;
		}
		ip->family = family;
		memcpy(&ip->ip, in_addr, family == AF_INET ? 4 : 16);
		ip++;
	}

	freeifaddrs(myaddrs);

	return cnt;
}

#endif  /* endif WINDOWS */

static const char *git_version()
{
	const char *v = GIT_VERSION;
	if (v && *v) {
		v = "-" GIT_VERSION;
	}
	else {
		v = "";
	}
	return v;
}

static void usage()
{
	printf("\n" PROGRAM_NAME " v" PROGRAM_VERSION "%s\n%s\n",
			git_version(), "\n\
Usage:\n\
\n\
http-proxy [-b BIND_ADDR] [-p BIND_PORT] [--config=CONFIG_PATH]\n\
         [--log=LOG_FILE_PATH] [--log-level=LOG_LEVEL]\n\
         [--chnroute=CHNROUTE_FILE] [--proxy=SOCKS5_PROXY]\n\
         [--daemon] [--pid=PID_FILE_PATH] [-v] [-V] [-h]\n\
\n\
Http proxy. With http-proxy, you can assign a socks5 proxy as upstream proxy.\n\
And, use \"chnroute\" to by pass proxy.\n\
\n\
Note:\n\
  With \"--chnroute\", you should make sure that the dns resolve result is clean.\n\
  You can use CleanDNS (https://github.com/GangZhuo/CleanDNS),\n\
  ChinaDNS (https://github.com/shadowsocks/ChinaDNS) or similar utilities to \n\
  get clean dns result.\n\
\n\
Options:\n\
\n\
  -b BIND_ADDR             Address that listens, default: " DEFAULT_LISTEN_ADDR ".\n\
                           Use comma to separate multi addresses, \n\
                           e.g. -b 127.0.0.1:1081,[::1]:1081.\n\
  -p BIND_PORT             Port that listen on, default: " DEFAULT_LISTEN_PORT ".\n\
                           The port specified in \"-b\" is priority .\n\
  -t TIMEOUT               Timeout (seconds), default: " XSTR(DEFAULT_TIMEOUT) ".");
#ifdef ASYN_DNS
	printf("%s\n", "\
  --dns-server=DNS_SERVER  DNS servers, e.g. 192.168.1.1:53,8.8.8.8.");
#endif
	printf("%s\n", "\
  --dns-timeout=TIMEOUT    DNS cache timeout (seconds), default: " XSTR(DEFAULT_DNS_TIMEOUT) ".\n\
                           0 mean no cache.\n\
  --daemon                 Daemonize.\n\
  --pid=PID_FILE_PATH      pid file, default: " DEFAULT_PID_FILE ", \n\
                           only available on daemonize.\n\
  --log=LOG_FILE_PATH      Write log to a file.\n\
  --log-level=LOG_LEVEL    Log level, range: [0, 7], default: " LOG_DEFAULT_LEVEL_NAME ".\n\
  --config=CONFIG_PATH     Config file, find sample at \n\
                           https://github.com/GangZhuo/http-proxy.\n\
  --chnroute=CHNROUTE_FILE Path to china route file, \n\
                           e.g.: --chnroute=lan.txt,chnroute.txt,chnroute6.txt.\n\
  --forbidden=FORBIDDEN_FILE Path to forbidden route file, \n\
                           e.g.: --forbidden=self.txt,youtube.txt.\n\
  --proxy=PROXY_URL        Proxy url, e.g. --proxy=socks5://127.0.0.1:1080\n\
                           or --proxy=http://username:password@[::1]:80. \n\
                           More than one proxy is supported,\n\
                           in the case, if first proxy is unconnectable, it is \n\
                           automatic to switch to next proxy.\n\
                           Only socks5 with no authentication and anonymous http proxy\n\
                           or basic authentication http proxy are supported.\n\
                           The http proxy must be support CONNECT method.\n\
  --ipv6-prefer            IPv6 preferential.\n\
  --fallback-no-proxy=[yes|no] \n\
                           If there are no proxy selected, then fall back to direct connect.\n\
  --reverse                Reverse. If set, then connect server by proxy, \n\
                           when the server's IP in the chnroute.\n\
  --resolve-on-server      Also resolve domain on proxy server.\n\
  --domains=DOMAINS_FILE   Domain files.\n\
  -v                       Verbose logging.\n\
  -h                       Show this help message and exit.\n\
  -V                       Print version and then exit.\n\
\n\
Online help: <https://github.com/GangZhuo/http-proxy>\n");
}

static int parse_args(int argc, char** argv)
{
	int ch;
	int option_index = 0;
	static struct option long_options[] = {
		{"daemon",     no_argument,       NULL, 1},
		{"pid",        required_argument, NULL, 2},
		{"log",        required_argument, NULL, 3},
		{"log-level",  required_argument, NULL, 4},
		{"config",     required_argument, NULL, 5},
		{"launch-log", required_argument, NULL, 6},
		{"proxy",      required_argument, NULL, 7},
		{"chnroute",   required_argument, NULL, 8},
		{"ipv6-prefer",no_argument,       NULL, 9},
		{"dns-timeout",required_argument, NULL, 10},
		{"dns-server", required_argument, NULL, 11},
		{"forbidden",  required_argument, NULL, 12},
		{"reverse",    no_argument,       NULL, 13},
		{"resolve-on-server",no_argument, NULL, 14},
		{"domains",    required_argument, NULL, 15},
		{"fallback-no-proxy",required_argument, NULL, 16},
		{0, 0, 0, 0}
	};

	while ((ch = getopt_long(argc, argv, "hb:p:t:vV", long_options, &option_index)) != -1) {
		switch (ch) {
		case 1:
			daemonize = 1;
			break;
		case 2:
			pid_file = strdup(optarg);
			break;
		case 3:
			log_file = strdup(optarg);
			break;
		case 4:
			loglevel = atoi(optarg);
			break;
		case 5:
			config_file = strdup(optarg);
			break;
		case 6:
			launch_log = strdup(optarg);
			break;
		case 7:
			proxy = strdup(optarg);
			break;
		case 8:
			chnroute = strdup(optarg);
			break;
		case 9:
			ipv6_prefer = 1;
			break;
		case 10:
			dns_timeout = atoi(optarg);
			break;
		case 11:
			dns_server = strdup(optarg);
			break;
		case 12:
			forbidden_file = strdup(optarg);
			break;
		case 13:
			reverse = 1;
			break;
		case 14:
			resolve_on_server = 1;
			break;
		case 15:
			domain_file = strdup(optarg);
			break;
		case 16:
			fallback_no_proxy = is_true_val(optarg);
			break;
		case 'h':
			usage();
			exit(0);
		case 'b':
			listen_addr = strdup(optarg);
			break;
		case 'p':
			listen_port = strdup(optarg);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'v':
			loglevel++;
			break;
		case 'V':
			printf(PROGRAM_NAME " v" PROGRAM_VERSION "%s\n", git_version());
			exit(0);
		default:
			usage();
			exit(1);
		}
	}

	return 0;
}

static int check_args()
{
	if (listen_addr == NULL) {
		listen_addr = strdup(DEFAULT_LISTEN_ADDR);
	}
	if (listen_port == NULL) {
		listen_port = strdup(DEFAULT_LISTEN_PORT);
	}
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT;
	}
	if (dns_timeout == -1) {
		dns_timeout = DEFAULT_DNS_TIMEOUT;
	}
	return 0;
}

static const char *get_proxy_type_name(int proxy_type)
{
	switch (proxy_type) {
		case HTTP_PROXY: return "http";
		case SOCKS5_PROXY: return "socks5";
		default: return "";
	}
}

static void print_args()
{
	int i;

	logn(PROGRAM_NAME " v" PROGRAM_VERSION "%s\n", git_version());

	for (i = 0; i < listen_num; i++) {
		logn("listen on %s\n",
			get_sockaddrname(&listens[i].addr));
	}
	logn("loglevel: %d\n", loglevel);
#ifndef WINDOWS
	if (daemonize) {
		logn("pid file: %s\n", pid_file);
	}
#endif
	if (log_file)
		logn("log_file: %s\n", log_file);

	if (chnroute)
		logn("chnroute: %s\n", chnroute);

	if (domain_file)
		logn("domains: %s\n", domain_file);

	if (forbidden_file)
		logn("forbidden: %s\n", forbidden_file);

	if (proxy) {
		logn("proxy: %s\n", proxy);
		logn("  \ttype\tipv4\tipv6\tauth\taddress\n");
		for (i = 0; i < proxy_num; i++) {
			proxy_t *proxy = proxy_list + i;
			logn("  %d\t%s\t%s\t%s\t%s\t%s\n",
					i + 1,
					get_proxy_type_name(proxy->proxy_type),
					proxy->is_support_ipv4 ? "yes" : "no",
					proxy->is_support_ipv6 ? "yes" : "no",
					strlen(proxy->username) > 0 ? "yes" : "no",
					get_sockaddrname(&proxy->addr));
		}
	}

	logn("fallback no proxy: %s\n", fallback_no_proxy ? "yes" : "no");
	logn("ipv6 prefer: %s\n", ipv6_prefer ? "yes" : "no");
	logn("connection timeout: %d\n", timeout);
	logn("dns cache timeout: %d\n", dns_timeout);
	logn("reverse: %s\n", reverse ? "yes" : "no");
	logn("resolve on proxy server: %s\n",
			resolve_on_server ? "yes" : "no");

#ifdef ASYN_DNS
	a_print_servers();
#endif

#ifdef _DEBUG
	print_local_ips(local_ips, local_ip_cnt);
#endif

	logn("\n");
}

static void parse_option(char* ln, char** option, char** name, char** value)
{
	char* p = ln;

	*option = p;
	*name = NULL;
	*value = NULL;

	while (*p && !isspace((int)(*((unsigned char*)p)))) p++;

	if (!(*p))
		return;

	*p = '\0';

	p = ltrim(p + 1);

	*name = p;

	while (*p && !isspace((int)(*((unsigned char*)p)))) p++;

	if (!(*p))
		return;

	*p = '\0';

	p = ltrim(p + 1);

	*value = trim_quote(p);
}

static int read_config_file(const char* config_file, int force)
{
	FILE* pf;
	char line[2048], * ln;
	char* option, * name, * value;
	int len = 0, cnf_index = -1;

	pf = fopen(config_file, "r");
	if (!pf) {
		loge("failed to open %s\n", config_file);
		return -1;
	}

	while (!feof(pf)) {
		memset(line, 0, sizeof(line));
		fgets(line, sizeof(line) - 1, pf);
		ln = line;
		ln = ltrim(ln);
		ln = rtrim(ln);
		if (*ln == '\0' || *ln == '#')
			continue;

		if (strncmp(ln, "config", 6) == 0 &&
			isspace(ln[6]) &&
			strncmp((ln = ltrim(ln + 6)), "cfg", 3) == 0 &&
			(ln[3] == '\0' || isspace((int)(*((unsigned char*)ln + 3))))) {
			cnf_index++;
			if (cnf_index > 0) /*only parse first 'config cfg'*/
				break;
			continue;
		}

		if (cnf_index != 0)
			continue;

		parse_option(ln, &option, &name, &value);

		if (strcmp(option, "option") != 0 || !name || !value || !(*name) || !(*value)) {
			loge("invalid option: %s %s %s\n", option, name, value);
			fclose(pf);
			return -1;
		}

		if (strcmp(name, "bind_addr") == 0 && strlen(value)) {
			if (force || !listen_addr) {
				if (listen_addr) free(listen_addr);
				listen_addr = strdup(value);
			}
		}
		else if (strcmp(name, "bind_port") == 0 && strlen(value)) {
			if (force || !listen_port) {
				if (listen_port) free(listen_port);
				listen_port = strdup(value);
			}
		}
		else if (strcmp(name, "timeout") == 0 && strlen(value)) {
			if (force || timeout == 0) {
				timeout = atoi(value);
			}
		}
		else if (strcmp(name, "pid_file") == 0 && strlen(value)) {
			if (force || !pid_file) {
				if (pid_file) free(pid_file);
				pid_file = strdup(value);
			}
		}
		else if (strcmp(name, "log_file") == 0 && strlen(value)) {
			if (force || !log_file) {
				if (log_file) free(log_file);
				log_file = strdup(value);
			}
		}
		else if (strcmp(name, "log_level") == 0 && strlen(value)) {
			if (force || loglevel == LOG_DEFAULT_LEVEL) {
				loglevel = atoi(value);
			}
		}
		else if (strcmp(name, "chnroute") == 0 && strlen(value)) {
			if (force || !chnroute) {
				if (chnroute) free(chnroute);
				chnroute = strdup(value);
			}
		}
		else if (strcmp(name, "proxy") == 0 && strlen(value)) {
			if (force || !proxy) {
				if (proxy) free(proxy);
				proxy = strdup(value);
			}
		}
		else if (strcmp(name, "ipv6_prefer") == 0 && strlen(value)) {
			if (force || !ipv6_prefer) {
				ipv6_prefer = is_true_val(value);
			}
		}
		else if (strcmp(name, "dns_timeout") == 0 && strlen(value)) {
			if (force || dns_timeout == -1) {
				dns_timeout = atoi(value);
			}
		}
		else if (strcmp(name, "dns_server") == 0 && strlen(value)) {
			if (force || !dns_server) {
				if (dns_server) free(dns_server);
				dns_server = strdup(value);
			}
		}
		else if (strcmp(name, "forbidden") == 0 && strlen(value)) {
			if (force || !forbidden_file) {
				if (forbidden_file) free(forbidden_file);
				forbidden_file = strdup(value);
			}
		}
		else if (strcmp(name, "reverse") == 0 && strlen(value)) {
			if (force || !reverse) {
				reverse = is_true_val(value);
			}
		}
		else if (strcmp(name, "resolve_on_server") == 0 && strlen(value)) {
			if (force || !resolve_on_server) {
				resolve_on_server = is_true_val(value);
			}
		}
		else if (strcmp(name, "domains") == 0 && strlen(value)) {
			if (force || !domain_file) {
				if (domain_file) free(domain_file);
				domain_file = strdup(value);
			}
		}
		else if (strcmp(name, "fallback_no_proxy") == 0 && strlen(value)) {
			if (force || fallback_no_proxy == -2) {
				fallback_no_proxy = is_true_val(value);
			}
		}
		else {
			/*do nothing*/
		}
	}

	fclose(pf);

	return 0;
}

static int parse_addrstr(char* s, char** host, char** port)
{
	char* p;
	int cnt = 0;

	/* ipv6 */
	if (*s == '[') {
		p = strrchr(s, ']');
		if (p) {
			*host = s + 1;
			*p = '\0';
			p++;
			if (*p == ':')
				*port = p + 1;
			else
				*port = NULL;
			return 0;
		}
		else {
			return -1;
		}
	}

	p = strrchr(s, ':');
	if (p) {
		*port = p + 1;
		*p = '\0';
	}
	else {
		*port = NULL;
	}

	*host = s;

	return 0;
}

static int host2addr(sockaddr_t* addr, const char* host, const char* port)
{
	struct addrinfo hints;
	struct addrinfo* addrinfo;
	int r;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = ipv6_prefer ? AF_INET6 : AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	r = getaddrinfo(host, port, &hints, &addrinfo);
	if (r == EAI_NODATA || r == EAI_ADDRFAMILY) {
		hints.ai_family = ipv6_prefer ? AF_INET : AF_INET6;
		r = getaddrinfo(host, port, &hints, &addrinfo);
	}

	if (r != 0)
	{
		loge("host2addr() error: retval=%d %s %s:%s\n",
			r, gai_strerror(r), host, port);
		return -1;
	}

	memcpy(&addr->addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
	addr->addrlen = (int)addrinfo->ai_addrlen;

	freeaddrinfo(addrinfo);

	return 0;
}

static int str2addr(
	const char* s, sockaddr_t* addr,
	const char* default_port)
{
	char* copy = strdup(s);
	char* host, * port;
	int r;

	if (parse_addrstr(copy, &host, &port)) {
		free(copy);
		return -1;
	}

	if (!port || strlen(port) == 0)
		port = (char*)default_port;

	if (!port || strlen(port) == 0)
		port = DEFAULT_LISTEN_PORT;

	r = host2addr(addr, host, port);

	free(copy);

	return r;
}

static int resolve_addrstr(
	const char* str,
	sockaddr_t* addrs,
	int max_num,
	int element_size,
	const char* default_port)
{
	char* s, *p;
	int i;
	sockaddr_t* addr;

	s = strdup(str);

	for (i = 0, p = strtok(s, ",");
		p && *p && i < max_num;
		p = strtok(NULL, ",")) {

		addr = (sockaddr_t*)(((char*)addrs) + (size_t)element_size * i);

		if (str2addr(p, addr, default_port)) {
			free(s);
			loge("resolve_addrstr() error: resolve \"%s\" failed\n", str);
			return -1;
		}

		i++;
	}

	free(s);

	return i;
}

static char *get_proxy_type(char *s, int *proxy_type)
{
	char *p;

	p = strstr(s, "://");

	if (!p) {
		/* socks5 default */
		*proxy_type = SOCKS5_PROXY;
		return s;
	}

	*p = '\0';
	if (strcmp(s, "socks5") == 0) {
		*proxy_type = SOCKS5_PROXY;
	}
	else if (strcmp(s, "http") == 0) {
		*proxy_type = HTTP_PROXY;
	}
	else {
		loge("get_proxy_type() error: unsupport proxy(%s), "
			"only \"socks5\" and \"http\" supported\n", s);
		*p = ':'; /* restore */
		return NULL;
	}

	*p = ':'; /* restore */
	p += strlen("://");

	return p;
}

static char *get_proxy_username_and_password(char *s, char *username, char *password)
{
	char *p, *colon;

	p = strchr(s, '@');

	if (!p) {
		*username = '\0';
		*password = '\0';
		return s;
	}

	*p = '\0';
	colon = strchr(s, ':');

	if (colon) {
		*colon = '\0';
		strncpy(username, s, PROXY_USERNAME_LEN - 1);
		strncpy(password, colon + 1, PROXY_PASSWORD_LEN - 1);
		*colon = ':';
	}
	else {
		strncpy(username, s, PROXY_USERNAME_LEN - 1);
		*password = '\0';
	}

	/* restore */
	*p = '@';

	if (strlen(username) == 0) {
		loge("get_proxy_username_and_password() error: no username\n");
		return NULL;
	}
	if (strlen(password) == 0) {
		loge("get_proxy_username_and_password() error: no password\n");
		return NULL;
	}

	++p;

	return p;
}

int parse_proxy_options(char *query, proxy_t *proxy)
{
	char *s, *p, *eq;

	for (s = query; s && *s; s = p) {
		p = strchr(s, '&');
		if (p)
			*p++ = '\0';
		eq = strchr(s, '=');
		if (!eq)
			continue;
		*eq = '\0';
		++eq;
		if (strnicmp(s, "ipv4", sizeof("ipv4")) == 0) {
			proxy->is_support_ipv4 = is_true_val(eq);
		}
		else if (strnicmp(s, "ipv6", sizeof("ipv6")) == 0) {
			proxy->is_support_ipv6 = is_true_val(eq);
		}
	}

	return 0;
}

static const char *get_proxy_default_port(int proxy_type)
{
	switch (proxy_type) {
		case SOCKS5_PROXY: return "1080";
		case HTTP_PROXY: return "80";
		default: return NULL;
	}
}

int str2proxy(const char *s, proxy_t *proxy)
{
	char *copy = strdup(s), *p;
	char *query;
	char *host, *port;
	int r;

	p = get_proxy_type(copy, &proxy->proxy_type);
	if (!p) {
		free(copy);
		return -1;
	}

	proxy->is_support_ipv4 = TRUE;
	proxy->is_support_ipv6 = TRUE;

	query = strchr(p, '?');
	if (query) {
		*query = '\0';
		++query;
		if (parse_proxy_options(query, proxy)) {
			free(copy);
			return -1;
		}
	}

	p = get_proxy_username_and_password(p, proxy->username, proxy->password);
	if (!p) {
		free(copy);
		return -1;
	}

	if (parse_addrstr(p, &host, &port)) {
		free(copy);
		return -1;
	}

	if (!port || strlen(port) == 0) {
		port = (char*)get_proxy_default_port(proxy->proxy_type);
		assert(port);
	}

	r = host2addr(&proxy->addr, host, port);

	free(copy);

	return r;
}

int str2proxies(
	const char* str,
	proxy_t* proxies,
	int max_num)
{
	char* s, * p;
	int i;
	proxy_t* proxy;

	s = strdup(str);

	for (i = 0, p = strtok(s, ",");
		p && *p && i < max_num;
		p = strtok(NULL, ",")) {

		proxy = proxies + i;

		if (str2proxy(p, proxy)) {
			free(s);
			loge("str2proxies() error: resolve \"%s\" failed\n", str);
			return -1;
		}

		i++;
	}

	free(s);

	return i;
}

static int resolve_listens()
{
	memset(listens, 0, sizeof(listens));

	listen_num = resolve_addrstr(
		listen_addr,
		&listens[0].addr,
		MAX_LISTEN,
		sizeof(listen_t),
		listen_port);

	if (listen_num == -1) {
		loge("resolve_listens() error: resolve \"%s\" failed\n",
			listen_addr);
		return -1;
	}

	if (listen_num == 0) {
		loge("no listen\n");
		return -1;
	}

	return 0;
}

static int init_listen(listen_t* ctx)
{
	sockaddr_t* addr;
	struct sockaddr* sockaddr;
	sock_t sock;

	addr = &ctx->addr;
	sockaddr = (struct sockaddr*)(&addr->addr);

	sock = socket(sockaddr->sa_family, SOCK_STREAM, IPPROTO_TCP);

	if (!sock) {
		loge("init_listen() error: create socket error. errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	if (setreuseaddr(sock) != 0) {
		loge("init_listen() error: set sock reuse address failed\n");
		close(sock);
		return -1;
	}

	if (setnonblock(sock) != 0) {
		loge("init_listen() error: set sock non-block failed\n");
		close(sock);
		return -1;
	}

	if (bind(sock, sockaddr, addr->addrlen) != 0) {
		loge("init_listen() error: bind() error: %s errno=%d, %s\n",
			get_sockaddrname(addr), errno, strerror(errno));
		close(sock);
		return -1;
	}

	if (listen(sock, LISTEN_BACKLOG) != 0) {
		loge("init_listen() error: listen() error: %s errno=%d, %s\n",
			get_sockaddrname(addr), errno, strerror(errno));
		close(sock);
		return -1;
	}

	ctx->sock = sock;

	return 0;
}

static int init_listens()
{
	int i, num = listen_num;
	listen_t* listen;

	for (i = 0; i < num; i++) {
		listen = listens + i;
		if (init_listen(listen) != 0) {
			loge("init_listens() error\n");
			return -1;
		}
	}

	return 0;
}

static conn_t* new_conn(sock_t sock, listen_t* listen)
{
	conn_t* conn = (conn_t*)malloc(sizeof(conn_t));
	if (!conn) {
		loge("new_conn() error: alloc");
		return NULL;
	}

	memset(conn, 0, sizeof(conn_t));

	conn->sock = sock;
	conn->listen = listen;
	conn->tm_start = OS_GetTickCount();

	http_parser_init(&conn->parser, HTTP_REQUEST);

	return conn;
}

static void free_conn(conn_t* conn)
{
	if (conn == NULL)
		return;
#ifdef ASYN_DNS
	if (conn->a_state) {
		conn->a_state->is_conn_destroyed = TRUE;
		conn->a_state->conn = NULL;
	}
#endif
	if (conn->sock) {
		close(conn->sock);
		conn->sock = 0;
	}
	if (conn->rsock) {
		close(conn->rsock);
		conn->rsock = 0;
	}
	stream_free(&conn->ws);
	stream_free(&conn->rws);
	stream_free(&conn->url);
	stream_free(&conn->field.name);
	stream_free(&conn->field.value);
	if (conn->proxy) {
		stream_free(&conn->proxy->rs);
		stream_free(&conn->proxy->ws);
		free(conn->proxy);
	}
	free(conn->host);
	free(conn->rhost);
	free(conn->rport);
}

static void destroy_conn(conn_t* conn)
{
	free_conn(conn);
	free(conn);
}

static inline void close_after(conn_t* conn, int interval)
{
	time_t t = time(NULL);
	conn->expire = t + interval;
}

static inline void update_expire(conn_t* conn)
{
	close_after(conn, timeout);
}

static inline int is_expired(conn_t* conn, time_t now)
{
	return conn->expire <= now;
}

#ifdef HTTP_PROXY_PRINT_DOMAINS
struct domain_print_state_t {
	int i;
};

static int domain_print(rbtree_t *tree, rbnode_t *n, void *state)
{
	domain_t *domain = rbtree_container_of(n, domain_t, node);
	struct domain_print_state_t *st = state;

	st->i++;

	logd("%d %s/%d\n", st->i, domain->domain, domain->proxy_index);

	return 0;
}
#endif

static int init_proxy_server()
{
	int i;

	if (log_file && *log_file) {
		open_logfile(log_file);
	}
	else if (launch_log && *launch_log) {
		open_logfile(launch_log);
	}

	if (config_file && *config_file) {
		if (read_config_file(config_file, FALSE)) {
			return -1;
		}

		if (log_file && *log_file) {
			open_logfile(log_file);
		}
	}

	if (check_args())
		return -1;

	if (dnscache_init())
		return -1;

	dnscache_timeout = dns_timeout;

	if (resolve_listens() != 0)
		return -1;

	if (init_listens() != 0)
		return -1;

	if (proxy) {
		proxy_num = str2proxies(
			proxy,
			proxy_list,
			MAX_PROXY);
		if (proxy_num == -1) {
			loge("init_proxy_server() error: resolve \"%s\" failed\n",
				proxy);
			return -1;
		}
		for (i = 0; i < proxy_num; i++) {
			proxy_list[i].proxy_index = i;
		}
	}

	if (chnroute) {
		if ((chnr = chnroute_create()) == NULL) {
			loge("init_proxy_server() error: chnroute_create()\n");
			return -1;
		}
		if (chnroute_parse(chnr, chnroute)) {
			loge("init_proxy_server() error: invalid chnroute \"%s\"\n", chnroute);
			return -1;
		}
	}

	if (forbidden_file) {
		if ((forb = chnroute_create()) == NULL) {
			loge("init_proxy_server() error: chnroute_create()\n");
			return -1;
		}
		if (chnroute_parse(forb, forbidden_file)) {
			loge("init_proxy_server() error: invalid chnroute \"%s\"\n", forbidden_file);
			return -1;
		}
	}

	if (domain_dic_init(&domains)) {
		loge("init_proxy_server() error: domain_dic_init()\n");
		return -1;
	}

	if (domain_file) {
		if (domain_dic_load_files(&domains, domain_file)) {
			loge("init_proxy_server() error: domain_dic_load_files()\n");
			return -1;
		}
#ifdef HTTP_PROXY_PRINT_DOMAINS
		/* make MFLAGS=-DHTTP_PROXY_PRINT_DOMAINS */
		{
			domain_t *domain;
			struct domain_print_state_t dpstate = { 0 };
			logd("\ndomains:\n");
			rbtree_foreach_print(&domains, domain_print, &dpstate);
			logd("\ntesting domain dictionary:\n");
			domain = domain_dic_lookup(&domains, "www.google.com");
			if (domain) {
				logd("www.google.com found: %s/%d\n", domain->domain, domain->proxy_index);
			}
			else {
				logd("www.google.com not found\n");
			}
			domain = domain_dic_lookup(&domains, "WWW.GOOGLE.COM");
			if (domain) {
				logd("WWW.GOOGLE.COM found: %s/%d\n", domain->domain, domain->proxy_index);
			}
			else {
				logd("WWW.GOOGLE.COM not found\n");
			}
			domain = domain_dic_lookup(&domains, "twitter.com");
			if (domain) {
				logd("twitter.com: %s/%d\n", domain->domain, domain->proxy_index);
			}
			else {
				logd("twitter.com not found\n");
			}
		}
#endif
	}

#ifdef ASYN_DNS

	if (init_ares() != 0)
		return -1;

#endif

	local_ip_cnt = get_local_ips(&local_ips);

	if (local_ip_cnt < 0) {
		loge("init_proxy_server() error: get_local_ips()\n");
		return -1;
	}

	return 0;
}

static void uninit_proxy_server()
{
	int i;

	for (i = 0; i < listen_num; i++) {
		listen_t* listen = listens + i;
		if (listen->sock)
			close(listen->sock);
	}

	listen_num = 0;

	{
		dlitem_t* cur, * nxt;
		conn_t* conn;

		dllist_foreach(&conns, cur, nxt, conn_t, conn, entry) {
			destroy_conn(conn);
		}

		dllist_init(&conns);
	}

	if (is_use_logfile()) {
		close_logfile();
	}

	if (is_use_syslog()) {
		close_syslog();
	}

	free(listen_addr);
	listen_addr = NULL;

	free(listen_port);
	listen_port = NULL;

	free(pid_file);
	pid_file = NULL;

	free(log_file);
	log_file = NULL;

	free(launch_log);
	launch_log = NULL;

	free(config_file);
	config_file = NULL;

	chnroute_free(chnr);
	chnr = NULL;

	free(chnroute);
	chnroute = NULL;

	chnroute_free(forb);
	forb = NULL;

	free(forbidden_file);
	forbidden_file = NULL;

	local_ip_cnt = 0;
	free(local_ips);
	local_ips = NULL;

	dnscache_free();

	domain_dic_free(&domains);

	proxy_num = 0;

#ifdef ASYN_DNS

	free_ares();

	free(dns_server);
	dns_server = NULL;

#endif
}

static int try_parse_as_ip4(sockaddr_t* addr, const char* host, const char* port)
{
	struct sockaddr_in* in = (struct sockaddr_in*)(&addr->addr);

	if (inet_pton(AF_INET, host, &in->sin_addr) == 1) {
		in->sin_family = AF_INET;
		in->sin_port = htons(atoi(port));
		addr->addrlen = sizeof(struct sockaddr_in);
		return TRUE;
	}

	return FALSE;
}

static int try_parse_as_ip6(sockaddr_t* addr, const char* host, const char* port)
{
	struct sockaddr_in6* in = (struct sockaddr_in6*)(&addr->addr);

	if (inet_pton(AF_INET6, host, &in->sin6_addr) == 1) {
		in->sin6_family = AF_INET6;
		in->sin6_port = htons(atoi(port));
		addr->addrlen = sizeof(struct sockaddr_in);
		return TRUE;
	}

	return FALSE;
}

static int try_parse_as_ip(sockaddr_t* addr, const char* host, const char* port)
{
	int need_query = 0;

	if (try_parse_as_ip4(addr, host, port))
		return TRUE;
	
	return try_parse_as_ip6(addr, host, port);
}

static int get_host(char** host, const char* url, struct http_parser_url* u)
{
	if (u->field_set & (1 << UF_HOST)) {
		*host = (char*)malloc((size_t)u->field_data[UF_HOST].len + 1);
		if (!(*host)) {
			loge("get_host_and_port() error: alloc");
			return -1;
		}
		memcpy(*host, url + u->field_data[UF_HOST].off, u->field_data[UF_HOST].len);
		(*host)[u->field_data[UF_HOST].len] = '\0';
	}
	else {
		loge("get_host() error: no \"host\"");
		return -1;
	}

	return 0;
}

static int get_port_by_schema(char** port, const char* url, struct http_parser_url* u)
{
	if (u->field_set & (1 << UF_SCHEMA)) {
		const char* schema = url + u->field_data[UF_SCHEMA].off;
		size_t schemalen = u->field_data[UF_SCHEMA].len;

		if (schemalen == sizeof("https") - 1 &&
			strnicmp(schema, "https", sizeof("https") - 1) == 0) {
			*port = strdup("443");
		}
		else if (schemalen == sizeof("http") - 1 &&
			strnicmp(schema, "http", sizeof("http") - 1) == 0) {
			*port = strdup("80");
		}
		else {
			loge("get_port_by_schema() error: no \"schema\"");
			return -1;
		}
	}
	else {
		loge("get_port_by_schema() error: no \"schema\"");
		return -1;
	}

	return 0;
}

static int get_port(char** port, const char* url, struct http_parser_url* u)
{
	if (u->field_set & (1 << UF_PORT)) {
		*port = (char*)malloc((size_t)u->field_data[UF_PORT].len + 1);
		if (!(*port)) {
			loge("get_host_and_port() error: alloc");
			return -1;
		}
		memcpy(*port, url + u->field_data[UF_PORT].off, u->field_data[UF_PORT].len);
		(*port)[u->field_data[UF_PORT].len] = '\0';
	}
	else if (get_port_by_schema(port, url, u)) {
		return -1;
	}

	return 0;
}

static int get_host_and_port(char** host, char** port,
	const char* url, size_t urllen, int is_connect)
{
	struct http_parser_url u;

	http_parser_url_init(&u);

	if (http_parser_parse_url(url, urllen, is_connect, &u)) {
		loge("get_host_and_port() error: parse \"%s\" failed\n", url);
		return -1;
	}

	if (get_host(host, url, &u)) {
		return -1;
	}

	if (get_port(port, url, &u)) {
		free(*host);
		return -1;
	}

	return 0;
}

static int get_remote_host_and_port(char** host, char** port, conn_t* conn)
{
	if (conn->mode == pm_tunnel || (!startwith(conn->url.array, "http://") && conn->host)) {
		char* copy = conn->mode == pm_tunnel ? strdup(conn->url.array) : strdup(conn->host);
		char *h, * p;

		if (parse_addrstr(copy, &h, &p)) {
			free(copy);
			loge("get_remote_host_and_port() error: parse \"%s\" failed\n", conn->url.array);
			return -1;
		}

		*host = strdup(h);

		if (!p || strlen(p) == 0)
			*port = strdup("80");
		else
			*port = strdup(p);

		free(copy);
	}
	else {
		if (get_host_and_port(host, port, conn->url.array, conn->url.size, 0)) {
			loge("get_remote_host_and_port() error: parse \"%s\" failed\n", conn->url.array);
			return -1;
		}
	}

	return 0;
}

static int get_remote_addr(sockaddr_t* addr, conn_t* conn, got_addr_callback cb)
{
	char *host = conn->rhost, *port = conn->rport;

	if (dns_timeout > 0 && dnscache_get(host, (char*)addr)) {
		if (addr->addr.ss_family == AF_INET)
			((struct sockaddr_in*)(&addr->addr))->sin_port = htons((uint16_t)atoi(port));
		else
			((struct sockaddr_in6*)(&addr->addr))->sin6_port = htons((uint16_t)atoi(port));
		logd("get_remote_addr(): hit dns cache - %s - %s:%s \n",
			get_sockaddrname(addr), host, port);
		(*cb)(addr, TRUE, conn, host, port);
		return 0;
	}

#ifdef ASYN_DNS
	if (a_get_addr(addr, host, port, conn, cb)) {
		loge("get_remote_addr() error: resolve \"%s:%s\" failed\n", host, port);
		return -1;
	}
#else
	if (host2addr(addr, host, port)) {
		loge("get_remote_addr() error: resolve \"%s:%s\" failed\n", host, port);
		return -1;
	}

	if (dns_timeout > 0) {
		if (dnscache_set(host, (char*)addr, sizeof(sockaddr_t))) {
			logw("on_got_remote_addr() error: set dns cache failed - %s\n", host);
		}
	}

	(*cb)(addr, FALSE, conn, host, port);
#endif

	return 0;
}

static int remove_dnscache(conn_t* conn)
{
	char* host = conn->rhost, * port = conn->rport;

	if (dns_timeout <= 0)
		return 0;

	if (!host) {
		logd("remove_dnscache() error: no 'host'\n", host);
		return -1;
	}

	if (dnscache_remove(host)) {
		logd("remove_dnscache() error: remove \"%s\" failed\n", host);
		return -1;
	}

	return 0;
}

static int on_remote_connected(conn_t* conn, int reuse)
{
	http_parser* parser = &conn->parser;

	logi("%s - %s:%s -  %s (%lu ms)\n",
		reuse ? "reuse remote connection" : "remote connected",
		conn->rhost,
		conn->rport,
		get_sockaddrname(&conn->raddr),
		OS_GetTickCount() - conn->tm_start);

	conn->is_remote_connected = 1;

	if (conn->mode == pm_tunnel) {
		if (stream_appendf(&conn->ws, "HTTP/%d.%d 200 Connection Established\r\n\r\n",
			parser->http_major,
			parser->http_minor) == -1) {
			loge("on_remote_connected() error: stream_appendf()");
			return -1;
		}
		conn->is_first_response = 2;

		logd("\nws:\n%s\n", conn->ws.array);
		logd("\nrws:\n%s\n", conn->rws.array);

		return handle_write(conn);
	}
	else {
		conn->is_first_response = 1;
		return handle_rwrite(conn);
	}
}

static int on_proxy_connected(conn_t* conn)
{
	logi("proxy[%d] connected - %s:%s (%lu ms)\n",
		conn->proxy_index,
		conn->rhost, conn->rport,
		OS_GetTickCount() - conn->tm_start);
	conn->proxy->status = ps_none;
	return proxy_handshake(conn);
}

static int handle_accept(listen_t* ctx)
{
	sock_t sock;
	sockaddr_t from = {
		.addr = {0},
		.addrlen = sizeof(struct sockaddr_storage),
	};
	conn_t* conn;

	sock = accept(ctx->sock, (struct sockaddr*) & from.addr, &from.addrlen);
	if (sock == -1) {
		loge("accept() error: errno=%d, %s \n",
			errno, strerror(errno));
		return -1;
	}
	logd("accept() from %s\n", get_sockaddrname(&from));

	if (setnonblock(sock) != 0) {
		loge("accept() error: set sock non-block failed - errno=%d, %s\n",
			errno, strerror(errno));
		close(sock);
		return -1;
	}

	if (setnodelay(sock) != 0) {
		loge("accept() error: set sock nodelay failed - errno=%d, %s\n",
			errno, strerror(errno));
		close(sock);
		return -1;
	}

	conn = new_conn(sock, ctx);
	if (!conn) {
		close(sock);
		return -1;
	}
	
	dllist_add(&conns, &conn->entry);

	update_expire(conn);

	return 0;
}

static int tcp_send(sock_t sock, stream_t* s)
{
	int rsize = stream_rsize(s);
	int nsend;

	if (rsize == 0)
		return 0;

	nsend = send(sock, s->array + s->pos, rsize, 0);
	if (nsend == -1) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("tcp_send() error: errno=%d, %s \n",
				err, strerror(err));
			return -1;
		}
		return 0;
	}
	else {
		s->pos += nsend;
		logd("tcp_send(): send %d bytes\n", nsend);
		if (stream_quake(s)) {
			loge("tcp_send() error: stream_quake()\n");
			return -1;
		}
		return nsend;
	}
}

static int handle_write(conn_t* conn)
{
	sock_t sock = conn->sock;
	stream_t* s = &conn->ws;
	int nsend;

	if (conn->is_first_response == 2) {
		/* sending the response for CONNECT method */
		conn->is_first_response = 1;
	}
	else if (conn->is_first_response) {
		logi("recv first response - %s (%lu ms)\n",
			conn->url.array,
			OS_GetTickCount() - conn->tm_start);
		conn->is_first_response = 0;
	}

	nsend = tcp_send(sock, s);

	if (nsend == -1)
		return -1;

	if (nsend == 0)
		return 0;

	conn->tx += nsend;

	logd("handle_write(): write to %s (%lu ms)\n",
			get_sockname(sock), OS_GetTickCount() - conn->tm_start);

	if (conn->status == cs_rsp_closing) {
		close_after(conn, 3);
	}
	else {
		update_expire(conn);
	}

	return 0;
}

static int proxy_write(conn_t* conn)
{
	sock_t sock = conn->rsock;
	stream_t* s = &conn->proxy->ws;
	int nsend;

	nsend = tcp_send(sock, s);

	if (nsend == -1)
		return -1;

	if (nsend == 0)
		return 0;

	logd("proxy_write(): write to %s\n", get_conn_proxyname(conn));

	if (stream_rsize(s) == 0) {
		s->pos = 0;
		s->size = 0;
	}

	update_expire(conn);

	return 0;
}

static int handle_rwrite(conn_t* conn)
{
	sock_t sock = conn->rsock;
	stream_t* s = &conn->rws;
	int nsend;

	nsend = tcp_send(sock, s);

	if (nsend == -1)
		return -1;

	if (nsend == 0)
		return 0;

	conn->rtx += nsend;

	logd("handle_rwrite(): write to %s:%s\n", conn->rhost, conn->rport);

	update_expire(conn);

	return 0;
}

static int check_head_size(conn_t *conn, size_t addend)
{
	conn->header_size += addend;
	if (conn->header_size > MAX_HEADER_SIZE)
		return -1;
	return 0;
}

static int on_message_begin(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);
	logd("METHOD: %s\n", http_method_str(parser->method));
	conn->header_size = 0;
	free(conn->host), conn->host = NULL;
	stream_reset(&conn->url);
	stream_reset(&conn->field.name);
	stream_reset(&conn->field.value);
	conn->field.status = fs_none;
	conn->is_first_line = TRUE;
	conn->tm_start = OS_GetTickCount();
	conn->is_first_response = 0;
	return 0;
}

static int on_url(http_parser* parser, const char* at, size_t length)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);

	if (check_head_size(conn, length))
		return -1;

	if (stream_writes(&conn->url, at, (int)length) == -1) {
		loge("on_url() error: stream_writes()\n");
		return -1;
	}

	logd("URL: %s\n", conn->url.array);

	return 0;
}

static int on_first_line_complete(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);
	if (parser->method != HTTP_CONNECT) {
		int r;
		const char *path = strchr(conn->url.array + sizeof("http://"), '/');
		if (!path || !(*path))
			path = "/";
		r = stream_appendf(&conn->rws, "%s %s HTTP/%d.%d\r\n",
			http_method_str(parser->method),
			path,
			parser->http_major,
			parser->http_minor);
		if (r == -1) {
			loge("on_first_line_complete() error: stream_appendf()\n");
			return -1;
		}
	}
	return 0;
}

static int detect_first_line_complete(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);
	if (conn->is_first_line) {
		conn->is_first_line = FALSE;
		on_first_line_complete(parser);
		return TRUE;
	}
	return FALSE;
}

static int on_field_complete(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);

	detect_first_line_complete(parser);

	logd("%s: %s\n",
		conn->field.name.array,
		conn->field.value.array);

	if (!conn->host && strnicmp(conn->field.name.array, "Host", sizeof("Host")) == 0) {
		conn->host = strdup(conn->field.value.array);
		if (!conn->host) {
			loge("on_field_complete() error: alloc()\n");
			return -1;
		}
	}

	if (parser->method != HTTP_CONNECT) {
		int r;
		if (strnicmp(conn->field.name.array, "Proxy-Connection", sizeof("Proxy-Connection")) == 0) {
			r = stream_appendf(&conn->rws, "Connection: %s\r\n",
				conn->field.value.array);
		}
		else {
			r = stream_appendf(&conn->rws, "%s: %s\r\n",
				conn->field.name.array,
				conn->field.value.array);
		}
		if (r == -1) {
			loge("on_field_complete() error: stream_appendf()\n");
			return -1;
		}
	}

	stream_reset(&conn->field.name);
	stream_reset(&conn->field.value);
	conn->field.status = fs_none;

	return 0;
}

static int on_header_field(http_parser* parser, const char* at, size_t length)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);

	if (check_head_size(conn, length))
		return -1;

	if (conn->field.status == fs_value) {
		if (on_field_complete(parser))
			return -1;
	}

	conn->field.status = fs_name;

	if (stream_writes(&conn->field.name, at, (int)length) == -1) {
		loge("on_header_field() error: stream_writes()\n");
		return -1;
	}

	return 0;
}

static int on_header_value(http_parser* parser, const char* at, size_t length)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);

	if (check_head_size(conn, length))
		return -1;

	conn->field.status = fs_value;
	
	if (stream_writes(&conn->field.value, at, (int)length) == -1) {
		loge("on_header_value() error: stream_writes()\n");
		return -1;
	}

	return 0;
}

static int connect_addr(sockaddr_t* addr, sock_t *psock, conn_status *pstatus)
{
	sock_t sock = *psock;

	if (sock == 0) {
		sock = socket(addr->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);

		if (!sock) {
			loge("connect_addr() error: create socket error. errno=%d, %s - %s\n",
				errno, strerror(errno), get_sockaddrname(addr));
			return ERR_CREATE_SOCKET;
		}

		if (setnonblock(sock) != 0) {
			loge("connect_addr() error: set sock non-block failed - %s\n",
				get_sockaddrname(addr));
			close(sock);
			return ERR_SET_NONBLOCK;
		}

		if (setnodelay(sock) != 0) {
			loge("connect_addr() error: set sock nodelay failed - %s\n",
				get_sockaddrname(addr));
			close(sock);
			return ERR_SET_NONBLOCK;
		}
	}

	if (connect(sock, (struct sockaddr*)(&addr->addr), addr->addrlen) != 0) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("connect_addr() error: errno=%d, %s - %s\n",
				errno, strerror(errno), get_sockaddrname(addr));
			if (sock != *psock) {
				logd("connect_addr(): close sock");
				close(sock);
			}
			return ERR_CONNECT;
		}
		else {
			*pstatus = cs_connecting;
		}
	}
	else {
		*pstatus = cs_connected;
	}

	*psock = sock;

	return 0;
}

static int create_response(conn_t* conn,
	int http_code,
	const char *name,
	const char *content)
{
	stream_t* s = &conn->ws;
	http_parser* parser = &conn->parser;
	int content_size = 0;
	if (content)
		content_size = (int)strlen(content);
	stream_reset(s);
	if (stream_appendf(s,
		"HTTP/%d.%d %d %s\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Connection: close\r\n"
		"Content-Length: %d\r\n"
		"\r\n"
		"%s",
		parser->http_major,
		parser->http_minor,
		http_code,
		name,
		content_size,
		content ? content : "") == -1) {
		loge("create_response() error: stream_appendf()");
		return -1;
	}
	return 0;
}

static int response_forbidden(conn_t* conn)
{
	int r = create_response(conn, 403, "Forbidden", "Forbidden");
	if (r) conn->status = cs_closing;
	else conn->status = cs_rsp_closing;
	return r;
}

static int response_not_found(conn_t* conn)
{
	int r = create_response(conn, 404, "Not Found", "Not Found");
	if (r) conn->status = cs_closing;
	else conn->status = cs_rsp_closing;
	return r;
}

static int response_500(conn_t* conn)
{
	int r = create_response(conn, 500, "Internal Server Error", "Invalid Proxy");
	if (r) conn->status = cs_closing;
	else conn->status = cs_rsp_closing;
	return r;
}

static void close_conn(conn_t* conn)
{
	conn->status = cs_closing;
}

static int connect_target(conn_t* conn)
{
	sockaddr_t* addr = &conn->raddr;

	logi("direct connecting - %s:%s - %s\n",
		conn->rhost,
		conn->rport,
		get_sockaddrname(addr));

	if (connect_addr(addr, &conn->rsock, &conn->status)) {
		return -1;
	}

	if (conn->status == cs_connected) {
		if (on_remote_connected(conn, 0)) {
			return -1;
		}
	}

	return 0;
}

static int select_proxy(conn_t* conn, int min_proxy_index)
{
	int i;
	int family = conn->raddr.addr.ss_family;
	proxy_t *proxy;

	for (i = min_proxy_index; i < proxy_num; i++) {
		proxy = proxy_list + i;
		if ((family == AF_INET && proxy->is_support_ipv4) ||
			(family == AF_INET6 && proxy->is_support_ipv6)) {
			conn->proxy_index = i;
			conn->by_proxy = TRUE;
			conn->by_pass = FALSE;
			return 0;
		}
	}

	if (fallback_no_proxy) {
		conn->by_proxy = FALSE;
		conn->by_pass = TRUE;
		logw("select_proxy(): no more %s proxy, fallback to no proxy %s\n",
				family == AF_INET ? "IPv4" : "IPv6",
				conn->host ? conn->host : conn->url.array);
		return 0;
	}
	else {
		loge("select_proxy() error: no more %s proxy %s\n",
				family == AF_INET ? "IPv4" : "IPv6",
				conn->host ? conn->host : conn->url.array);
		return -1;
	}
}

static int do_connect(conn_t *conn, int min_proxy_index);

static int on_connect_proxy_failed(conn_t* conn)
{
	int min_proxy_index;

	min_proxy_index = conn->proxy_index + 1;

	logd("failed connect to proxy %s, switch to next %d\n",
		get_conn_proxyname(conn),
		min_proxy_index);

	/* reset proxy flags, so can choose proxy again */
	conn->by_proxy = conn->by_pass = FALSE;

	return do_connect(conn, min_proxy_index);
}

static int connect_proxy(int proxy_index, conn_t* conn)
{
	int r;

	logi("proxy[%d] connecting - %s:%s - %s\n",
		proxy_index,
		conn->rhost,
		conn->rport,
		get_sockaddrname(&conn->raddr));

	conn->by_proxy = TRUE;
	conn->by_pass = FALSE;
	conn->proxy_index = proxy_index;

	if (conn->proxy) {
		stream_free(&conn->proxy->rs);
		stream_free(&conn->proxy->ws);
	}
	else {
		conn->proxy = (proxy_ctx*)malloc(sizeof(proxy_ctx));
		if (!conn->proxy)
			return -1;
	}

	memset(conn->proxy, 0, sizeof(proxy_ctx));

	if ((r = connect_addr(
		&get_proxyinfo(proxy_index)->addr,
		&conn->rsock,
		&conn->status)) != 0) {
		if (r == ERR_CONNECT) {
			return on_connect_proxy_failed(conn);
		}
		return -1;
	}

	if (conn->status == cs_connected) {
		if (on_proxy_connected(conn)) {
			return -1;
		}
	}

	return 0;
}

static int by_proxy(conn_t* conn)
{
	int in_chnroute = FALSE;

	if (proxy_num == 0)
		return FALSE;

	if (chnr) {
		struct sockaddr* addr = (struct sockaddr*)&conn->raddr.addr;
		if (chnroute_test(chnr, addr))
			in_chnroute = TRUE;
	}

	if (reverse)
		return in_chnroute;

	return !in_chnroute;
}

static int do_connect(conn_t *conn, int min_proxy_index)
{
	int r;

	if (!conn->by_proxy && !conn->by_pass) {
		conn->by_proxy = by_proxy(conn);
		conn->by_pass = !conn->by_proxy;
		if (conn->by_proxy && select_proxy(conn, min_proxy_index)) {
			loge("do_connect() error: no supported proxy %s\n",
				conn->host ? conn->host : conn->url.array);
			return -1;
		}
	}

	if (conn->by_proxy && conn->proxy_index >= 0) {
		r = connect_proxy(conn->proxy_index, conn);
		if (r != 0) {
			loge("do_connect() error: connect proxy failed %s\n",
					conn->host ? conn->host : conn->url.array);
			return -1;
		}
	}
	else {
		r = connect_target(conn);
		if (r != 0) {
			loge("do_connect() error: connect remote failed %s\n",
					conn->host ? conn->host : conn->url.array);
			return -1;
		}
	}

	return 0;
}

static void on_got_remote_addr(sockaddr_t* addr, int hit_cache, conn_t* conn,
	const char* host, const char* port)
{
	int r;

	if (!addr) {
		loge("on_got_remote_addr() error: get remote address failed %s\n",
				conn->host ? conn->host : conn->url.array);
		close_conn(conn);
		return;
	}

	logi("domain resloved - %s:%s - %s%s (%lu ms)\n",
		host, port,
		get_sockaddrname(addr),
		hit_cache ? " (cache)" : "",
		OS_GetTickCount() - conn->tm_start);

	if (is_forbidden(addr)) {
		loge("on_got_remote_addr() error: forbidden %s\n",
				conn->host ? conn->host : conn->url.array);
		close_conn(conn);
		return;
	}

	r = do_connect(conn, 0);
	if (r != 0) {
		close_conn(conn);
		return;
	}
}

static int connect_remote(conn_t* conn)
{
	char *host = NULL, *port = NULL;
	domain_t *domain = NULL;
	sockaddr_t* addr = &conn->raddr;

	if (get_remote_host_and_port(&host, &port, conn)) {
		loge("connect_remote() error: no 'host' and 'port' %s\n",
				conn->host ? conn->host : conn->url.array);
		close_conn(conn);
		return -1;
	}

	logi("%s %s:%s\n",
		http_method_str(conn->parser.method),
		host, port);

	if (conn->rsock) {
		if (strcasecmp(conn->rhost, host) == 0 &&
				strcasecmp(conn->rport, port) == 0) {
			free(host);
			free(port);
			return on_remote_connected(conn, 1);
		}
		else {
			logi("close unmatch remote connection %s:%s\n", conn->rhost, conn->rport);
			free(conn->rhost), conn->rhost = NULL;
			free(conn->rport), conn->rport = NULL;
			close(conn->rsock), conn->rsock = 0;
			conn->by_proxy = FALSE;
			conn->by_pass = FALSE;
			conn->proxy_index = 0;
			if (conn->proxy) {
				stream_free(&conn->proxy->rs);
				stream_free(&conn->proxy->ws);
				free(conn->proxy);
				conn->proxy = NULL;
			}
			conn->status = cs_none;
		}
	}

	conn->rhost = host;
	conn->rport = port;

	/* if proxy is specified, first to determine the proxy base on the domain name */
	if (proxy_num > 0) {
		unsigned long tm = OS_GetTickCount();
		domain = domain_dic_lookup(&domains, host);
		logd("domain_dic_lookup %lu ms\n", OS_GetTickCount() - tm);
	}

	if (domain) {
		if (domain->proxy_index >= 0) {
			conn->by_proxy = TRUE;
			conn->by_pass = FALSE;
			logd("[domain] %s/%d by proxy %s\n",
					domain->domain, domain->proxy_index,
					conn->host ? conn->host : conn->url.array);
			if (connect_proxy(MIN(domain->proxy_index, proxy_num - 1), conn)) {
				loge("connect_remote() error: connect proxy failed %s\n",
						conn->host ? conn->host : conn->url.array);
				close_conn(conn);
				return -1;
			}
			return 0;
		}
		else if (domain->proxy_index == DOMAIN_FORBIDDEN) {
			logd("[domain] %s/%d forbidden %s\n",
					domain->domain, domain->proxy_index,
					conn->host ? conn->host : conn->url.array);
			loge("connect_remote() error: forbidden %s\n",
					conn->host ? conn->host : conn->url.array);
			close_conn(conn);
			return -1;
		}
		else if (domain->proxy_index == DOMAIN_BY_PASS) {
			conn->by_proxy = FALSE;
			conn->by_pass = TRUE;
			logd("[domain] %s/%d by pass %s\n",
					domain->domain, domain->proxy_index,
					conn->host ? conn->host : conn->url.array);
		}
		else {
			logw("[domain] %s/%d unknown option, fall back to determine by ip %s\n",
					domain->domain, domain->proxy_index,
					conn->host ? conn->host : conn->url.array);
		}
	}

	if (get_remote_addr(addr, conn, on_got_remote_addr)) {
		loge("connect_remote() error: get remote address failed %s\n",
				conn->host ? conn->host : conn->url.array);
		close_conn(conn);
		return -1;
	}

	return 0;
}

static int on_headers_complete(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);

	if (conn->field.status != fs_none) {
		if (on_field_complete(parser))
			return -1;
	}
	else {
		detect_first_line_complete(parser);
	}

	logd("on_headers_complete(): keep_alive=%d (%lu ms)\n",
			http_should_keep_alive(parser),
			OS_GetTickCount() - conn->tm_start);

	if (parser->method != HTTP_CONNECT) {
		if (stream_appendf(&conn->rws, "\r\n") == -1) {
			loge("on_headers_complete() error: stream_appendf()\n");
			return -1;
		}
		conn->mode = pm_proxy;
		conn->is_first_response = 1;
	}
	else {
		conn->mode = pm_tunnel;
		conn->is_first_response = 0;
	}

	if (connect_remote(conn))
		return -1;

	return 0;
}

static int on_body(http_parser* parser, const char* at, size_t length)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);
	logd("on_body(): %d bytes\n", (int)length);
	if (stream_appends(&conn->rws, at, (int)length) == -1) {
		loge("on_body() error: stream_appends()\n");
		return -1;
	}
	return 0;
}

static int on_chunk_header(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);
	logd("on_chunk_header(): %" PRIu64 " bytes\n", parser->content_length);
	if (stream_appendf(&conn->rws, "%x\r\n", parser->content_length) == -1) {
		loge("on_chunk_header() error: stream_appendf()\n");
		return -1;
	}
	return 0;
}

static int on_chunk_complete(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);
	logd("on_chunk_complete()\n");
	if (stream_appends(&conn->rws, "\r\n", 2) == -1) {
		loge("on_chunk_complete() error: stream_appends()\n");
		return -1;
	}
	return 0;
}

static int on_message_complete(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);
	logd("on_message_complete() (%lu ms)\n",
			OS_GetTickCount() - conn->tm_start);
	return 0;
}

static int tcp_recv(sock_t sock, char * buf, int buflen)
{
	int nread;

	nread = recv(sock, buf, buflen, 0);
	if (nread == -1) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("tcp_recv() error: errno=%d, %s\n",
				err, strerror(err));
			return -1;
		}
		return 0;
	}
	else if (nread == 0) {
		logd("tcp_recv(): connection closed by peer\n");
		return -2;
	}
	else {
		logd("tcp_recv(): recv %d bytes\n", nread);

		return nread;
	}
}

static int handle_recv(conn_t* conn)
{
	int nread;
	char buffer[BUF_SIZE];

	nread = tcp_recv(conn->sock, buffer, sizeof(buffer));

	if (nread < 0) {
		if (nread == -1) {
			loge("handle_recv() error - %s\n",
				conn->host ? conn->host : conn->url.array);
		}
		return -1;
	}

	if (nread == 0)
		return 0;

	conn->rx += nread;

	logd("handle_recv(): recv from %s\n", get_sockname(conn->sock));

	if (conn->mode == pm_tunnel) {
		if (!conn->is_remote_connected) {
			loge("handle_recv() error: new data received during CONNECT handshake\n");
			return -1;
		}
		else if (stream_appends(&conn->rws, buffer, nread) == -1) {
			loge("handle_recv() error: stream_appends()\n");
			return -1;
		}
	}
	else {
		size_t nparsed;
		http_parser_settings req_settings = {
			.on_message_begin = on_message_begin,
			.on_url = on_url,
			.on_status = NULL,
			.on_header_field = on_header_field,
			.on_header_value = on_header_value,
			.on_headers_complete = on_headers_complete,
			.on_body = on_body,
			.on_message_complete = on_message_complete,
			.on_chunk_header = on_chunk_header,
			.on_chunk_complete = on_chunk_complete,
		};

		nparsed = http_parser_execute(&conn->parser, &req_settings, buffer, nread);

		if (nparsed <= 0) {
			loge("handle_recv() error: %s\n", http_errno_name(conn->parser.http_errno));
			return -1;
		}
	}

	update_expire(conn);

	return 0;
}

static char* sin_port_to_bytes(uint16_t port)
{
	static char bytes[2];
	union {
		uint16_t port;
		struct {
			char bytes0;
			char bytes1;
		} bytes;
	} v;

	v.port = port;

	bytes[0] = v.bytes.bytes0;
	bytes[1] = v.bytes.bytes1;

	return bytes;
}

static int socks5_write_addr(stream_t *s, struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in* in = (struct sockaddr_in*)addr;

		if (stream_appends(s, "\x5\x1\0\x1", 4) == -1) {
			loge("socks5_write_addr() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, (const char*)& in->sin_addr, 4) == -1) {
			loge("socks5_write_addr() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, sin_port_to_bytes(in->sin_port), 2) == -1) {
			loge("socks5_write_addr() error: stream_appends()\n");
			goto err;
		}
	}
	else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6* in = (struct sockaddr_in6*)addr;

		if (stream_appends(s, "\x5\x1\0\x4", 4) == -1) {
			loge("socks5_write_addr() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, (const char*)& in->sin6_addr, 16) == -1) {
			loge("socks5_write_addr() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, sin_port_to_bytes(in->sin6_port), 2) == -1) {
			loge("socks5_write_addr() error: stream_appends()\n");
			goto err;
		}
	}
	else {
		loge("socks5_write_addr() error: unknown address family\n");
		goto err;
	}

	return 0;

  err:
	return -1;
}

static int socks5_write_host_port(stream_t *s, const char *host, const char *port)
{
	unsigned char host_len = (unsigned char)strlen(host);

	if (stream_appends(s, "\x5\x1\0\x3", 4) == -1) {
		loge("socks5_write_host_port() error: stream_appends()\n");
		goto err;
	}

	if (stream_appends(s, (const char *)&host_len, 1) == -1) {
		loge("socks5_write_host_port() error: stream_appends()\n");
		goto err;
	}

	if (stream_appends(s, host, host_len) == -1) {
		loge("socks5_write_host_port() error: stream_appends()\n");
		goto err;
	}

	if (stream_appends(s, sin_port_to_bytes(htons(atoi(port))), 2) == -1) {
		loge("socks5_write_host_port() error: stream_appends()\n");
		goto err;
	}

	return 0;

  err:
	return -1;
}

static int socks5_handshake3(conn_t* conn)
{
	stream_t *s = &conn->proxy->rs;
	char *buf = s->array;
	int buflen = s->size;

	if (buflen >= 10 && buf[0] == 0x5 && buf[3] == 0x1) {
		free(conn->proxy);
		conn->proxy = NULL;
		logd("socks5_handshake3(): socks5 handshaked (%lu ms)\n",
				OS_GetTickCount() - conn->tm_start);
		return on_remote_connected(conn, 0);
	}
	else {
		loge("socks5_handshake3() error: reject by proxy server\n");
		return -1;
	}
}

static int socks5_handshake2(conn_t* conn)
{
	struct sockaddr* addr = (struct sockaddr*) & conn->raddr.addr;
	socklen_t addrlen = conn->raddr.addrlen;
	stream_t* s;

	s = &conn->proxy->ws;

	/* clear send stream */
	s->pos = 0;
	s->size = 0;

	if (resolve_on_server || addrlen == 0) {
		if (socks5_write_host_port(s, conn->rhost, conn->rport)) {
			goto err;
		}
	}
	else {
		if (socks5_write_addr(s, addr)) {
			goto err;
		}
	}

	if (loglevel >= LOG_DEBUG) {
		logd("socks5 data:\n");
		bprint(s->array, s->size);
	}

	/* clear receive stream, and waiting data */
	conn->proxy->rs.pos = 0;
	conn->proxy->rs.size = 0;
	conn->proxy->status = ps_handshake1;

	return proxy_write(conn);

  err:
	return -1;
}

static int socks5_handshake1(conn_t* conn)
{
	stream_t *s = &conn->proxy->rs;
	char *buf = s->array;
	int buflen = s->size;

	if (buflen >= 2 && buf[0] == 0x5 && buf[1] == 0x0) {
		return socks5_handshake2(conn);
	}
	else {
		loge("socks5_handshake1() error: reject by proxy server\n");
		return -1;
	}
}

static int socks5_handshake0(conn_t *conn)
{
	stream_t *s = &conn->proxy->ws;

	if (stream_appends(s, "\x5\x1\0", 3) == -1) {
		loge("socks5_handshake0() error: stream_appends()\n");
		return -1;
	}

	/* clear receive stream, and waiting data */
	conn->proxy->rs.pos = 0;
	conn->proxy->rs.size = 0;
	conn->proxy->status = ps_handshake0;

	return proxy_write(conn);
}

static int socks5_handshake(conn_t *conn)
{
	switch (conn->proxy->status) {
		case ps_none:
			return socks5_handshake0(conn);
		case ps_handshake0:
			return socks5_handshake1(conn);
		case ps_handshake1:
			return socks5_handshake3(conn);
		default:
			loge("socks5_handshake() error: unknown proxy status\n");
			return -1;
	}
	return 0;
}

static int hp_handshake1(conn_t *conn)
{
	stream_t *s = &conn->proxy->rs;
	const char *p;
	int header_len = 0;
	int http_code = 0;

	logd("hp_handshake1(): recv\r\n%s\n", s->array);

	if ((p = strstr(s->array, "\r\n\r\n"))) {
		header_len = (int)(p - s->array) + 4;
		if (s->size > sizeof("HTTP/1.1 XXX") && strncmp(s->array, "HTTP/", 5) == 0 &&
			(p = strchr(s->array, ' ')) != NULL) {
			char http_code_str[4];
			strncpy(http_code_str, p + 1, sizeof(http_code_str));
			http_code_str[3] = '\0';
			http_code = atoi(http_code_str);
			if (http_code != 200 && (p = strstr(s->array, "Content-Length:"))) {
				char content_length_str[256];
				p += sizeof("Content-Length:") - 1;
				char* en = strchr(p, '\n');
				if (en && (en - p) < sizeof(content_length_str)) {
					int content_length;
					memcpy(content_length_str, p, en - p);
					content_length_str[en - p] = '\0';
					content_length = atoi(ltrim(rtrim(content_length_str)));
					if (header_len + content_length > s->size) {
						http_code = 0; /* waiting http body */
					}
				}
			}
		}
		else {
			http_code = -1; /* not a HTTP response */
		}
	}
	else {
		/* do nothing, just wait for full header data */
	}

	if (http_code == 200) {
		free(conn->proxy);
		conn->proxy = NULL;
		logd("hp_handshake1(): http proxy handshaked (%lu ms)\n",
				OS_GetTickCount() - conn->tm_start);
		return on_remote_connected(conn, 0);
	}
	else if (http_code != 0 && http_code != 200) {
		if (loglevel >= LOG_DEBUG) {
			loge("hp_handshake1() error: http_code=%d - %s:%s\n%s\n",
				http_code, conn->rhost, conn->rport, s->array);
		}
		else {
			loge("hp_handshake1() error: http_code=%d - %s:%s\n",
				http_code, conn->rhost, conn->rport);
		}
		return -1;
	}

	return 0;
}

static int hp_handshake0(conn_t *conn)
{
	const proxy_t *proxy = proxy_list + conn->proxy_index;
	stream_t *s = &conn->proxy->ws;
	struct sockaddr_t* target_addr = &conn->raddr;
	socklen_t addrlen = conn->raddr.addrlen;
	char target_host[512];
	const int authorization = strlen(proxy->username) > 0;
	char *auth_code = NULL;
	int auth_code_len = 0;
	int r;

	if (resolve_on_server || addrlen == 0) {
		snprintf(target_host, sizeof(target_host), "%s:%s", conn->rhost, conn->rport);
	}
	else {
		strncpy(target_host, get_sockaddrname(target_addr), sizeof(target_host));
	}

	target_host[sizeof(target_host) - 1] = '\0';

	if (authorization) {
		char auth_str[PROXY_USERNAME_LEN + PROXY_PASSWORD_LEN];
		sprintf(auth_str, "%s:%s", proxy->username, proxy->password);
		auth_code = base64url_encode((const unsigned char*)auth_str,
			strlen(auth_str), &auth_code_len, TRUE);
	}

	r = stream_writef(s,
		"CONNECT %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: "PROGRAM_NAME"/"PROGRAM_VERSION"\r\n"
		"Proxy-Connection: keep-alive\r\n"
		"Connection: keep-alive\r\n"
		"%s%s%s"
		"\r\n",
		target_host,
		target_host,
		authorization ? "Proxy-Authorization: Basic " : "",
		authorization ? auth_code : "",
		authorization ? "\r\n" : "");

	if (r == -1) {
		loge("hp_handshake0() error: stream_writef()\n");
		free(auth_code);
		return -1;
	}

	free(auth_code);

	logd("hp_handshake0(): send\r\n%s\n", s->array);

	s->pos = 0;

	/* clear receive stream, and waiting data */
	conn->proxy->rs.pos = 0;
	conn->proxy->rs.size = 0;
	conn->proxy->status = ps_handshake0;

	return proxy_write(conn);
}

static int hp_handshake(conn_t *conn)
{
	switch (conn->proxy->status) {
		case ps_none:
			return hp_handshake0(conn);
		case ps_handshake0:
			return hp_handshake1(conn);
		default:
			loge("hp_handshake() error: unknown proxy status\n");
			return -1;
	}
	return -1;
}

static int proxy_handshake(conn_t *conn)
{
	const proxy_t *proxy = proxy_list + conn->proxy_index;

	switch (proxy->proxy_type) {
		case SOCKS5_PROXY:
			return socks5_handshake(conn);
		case HTTP_PROXY:
			return hp_handshake(conn);
		default:
			loge("proxy_handshake() error: unsupport proxy type\n");
			return -1;
	}
}

static int proxy_recv(conn_t* conn)
{
	int nread, err;
	stream_t* s = &conn->proxy->rs;

	if (stream_rcap(s) < 1024) {
		int new_cap = MAX(s->cap * 2, 1024);
		if (stream_set_cap(s, new_cap)) {
			return -1;
		}
	}

	nread = tcp_recv(conn->rsock, s->array + s->pos, s->cap - s->pos - 1);

	if (nread < 0) {
		if (nread == -1) {
			loge("proxy_recv() error - %s\n",
				conn->host ? conn->host : conn->url.array);
		}
		return -1;
	}

	if (nread == 0)
		return 0; /* EAGAIN */

	logd("proxy_recv(): recv from %s\n", get_conn_proxyname(conn));

	s->pos += nread;
	s->size += nread;
	s->array[s->pos] = '\0';

	if (s->size >= HTTP_MAX_HEADER_SIZE) {
		loge("proxy_recv() error: received too large (>= %s bytes)"
			" proxy handshake data\n", s->pos);
		return -1;
	}

	err = proxy_handshake(conn);

	if (!err) {
		update_expire(conn);
	}

	return err;
}

static int handle_rrecv(conn_t* conn)
{
	int nread;
	char buffer[BUF_SIZE];

	nread = tcp_recv(conn->rsock, buffer, sizeof(buffer));

	if (nread < 0) {
		if (nread == -1) {
			loge("handle_rrecv() error - %s\n",
				conn->host ? conn->host : conn->url.array);
		}
		return -1;
	}

	if (nread == 0)
		return 0;

	conn->rrx += nread;

	logd("handle_rrecv(): recv from %s:%s\n", conn->rhost, conn->rport);

	if (stream_appends(&conn->ws, buffer, nread) == -1) {
		loge("handle_rrecv() error: stream_appends()\n");
		return -1;
	}

	update_expire(conn);

	return 0;
}

static int do_loop()
{
	fd_set readset, writeset, errorset;
	sock_t max_fd;
	int i, r;
	time_t now;

	running = 1;
	while (running) {
		struct timeval timeout = {
			.tv_sec = 0,
			.tv_usec = 10 * 1000,
		};

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_ZERO(&errorset);


#ifdef ASYN_DNS
		max_fd = ares_fds(a_channel, &readset, &writeset);
#else
		max_fd = 0;
#endif

		for (i = 0; i < listen_num; i++) {
			listen_t* listen = listens + i;

			if (!running) break;

			max_fd = MAX(max_fd, listen->sock);

			FD_SET(listen->sock, &readset);
			FD_SET(listen->sock, &errorset);
		}

		{
			dlitem_t* cur, * nxt;
			conn_t* conn;
			int is_local_sending;
			int is_local_handshaked;
			int is_local_reading;
			int is_remote_connected;
			int is_remote_sending;
			int is_closing;
			int is_local_fdset;

			dllist_foreach(&conns, cur, nxt, conn_t, conn, entry) {

				if (!running) break;

				is_local_sending = stream_rsize(&conn->ws) > 0;

				is_local_handshaked = conn->mode != ps_none;

				is_remote_connected = conn->rsock > 0 &&
					conn->status == cs_connected &&
					!conn->proxy;

				is_remote_sending = conn->rsock > 0 &&
					(conn->status == cs_connecting ||
					 (!conn->proxy && stream_rsize(&conn->rws) > 0) ||
					 (conn->proxy && stream_rsize(&conn->proxy->ws) > 0));

				is_closing = conn->status == cs_closing ||
					conn->status == cs_rsp_closing;

				is_local_reading = !is_closing &&
					(!is_local_handshaked || !is_remote_sending) &&
					conn->rws.size < MAX_BUF_SIZE;

				is_local_fdset = 0;

				if (is_local_sending && conn->status != cs_closing) {
					FD_SET(conn->sock, &writeset);
					is_local_fdset = 1;
				}
				else if (is_local_reading) {
					FD_SET(conn->sock, &readset);
					is_local_fdset = 1;
				}
				if (!is_closing) {
					FD_SET(conn->sock, &errorset);
					is_local_fdset = 1;
				}
				if (is_local_fdset) {
					max_fd = MAX(max_fd, conn->sock);
				}

				if (!is_closing && conn->rsock > 0) {
					max_fd = MAX(max_fd, conn->rsock);
					if (is_remote_sending)
						FD_SET(conn->rsock, &writeset);
					else if (!is_local_sending)
						FD_SET(conn->rsock, &readset);
					FD_SET(conn->rsock, &errorset);
				}
			}
		}

		if (!running) break;

		if (select(max_fd + 1, &readset, &writeset, &errorset, &timeout) == -1) {
			if (errno == EINTR) {
				logd("select(): errno=%d, %s \n", errno, strerror(errno));
				if (!running)
					break;
				continue;
			}
			else {
				loge("select() error: errno=%d, %s \n",
					errno, strerror(errno));
				return -1;
			}
		}

		if (!running) break;

		now = time(NULL);

#ifdef ASYN_DNS
		ares_process(a_channel, &readset, &writeset);
#endif

		for (i = 0; i < listen_num; i++) {
			listen_t* listen = listens + i;

			if (!running) break;

			if (FD_ISSET(listen->sock, &errorset)) {
				loge("do_loop(): listen.sock error\n");
				return -1;
			}

			if (FD_ISSET(listen->sock, &readset)) {
				r = handle_accept(listen);
			}
		}

		{
			dlitem_t* cur, * nxt;
			conn_t* conn;

			dllist_foreach(&conns, cur, nxt, conn_t, conn, entry) {

				if (!running) break;

				if (conn->status == cs_closing) {
					r = -1;
				}
				else if (FD_ISSET(conn->sock, &errorset)) {
					int err = getsockerr(conn->sock);
					loge("do_loop(): conn.sock error (%s%s%s%s%s%s%s): errno=%d, %s \n",
						get_sockname(conn->sock),
						conn->rhost ? " => " : "",
						conn->rhost ? get_sockaddrname(&conn->raddr) : "",
						conn->rhost ? " - " : "",
						conn->rhost ? conn->rhost : "",
						conn->rhost ? ":" : "",
						conn->rport ? conn->rport : "",
						err, strerror(err));
					r = -1;
				}
				else if (FD_ISSET(conn->sock, &writeset)) {
					r = handle_write(conn);
				}
				else if (FD_ISSET(conn->sock, &readset)) {
					r = handle_recv(conn);
				}
				else {
					r = 0;
				}

				if (!running) break;

				if (!r && conn->rsock > 0) {
					if (FD_ISSET(conn->rsock, &errorset)) {
						int err = getsockerr(conn->rsock);
						loge("do_loop(): conn.rsock error (%s => %s - %s:%s): errno=%d, %s \n",
							get_sockname(conn->sock),
							get_sockaddrname(&conn->raddr),
							conn->rhost,
							conn->rport,
							err, strerror(err));
						r = -1;
						if (err == WSAETIMEDOUT || err == ETIMEDOUT) {
							remove_dnscache(conn);
						}
						if (conn->proxy) {
							r = on_connect_proxy_failed(conn);
						}
					}
					else if (FD_ISSET(conn->rsock, &writeset)) {
						if (conn->status == cs_connecting) {
							int err = getsockerr(conn->rsock);
							if (err) {
								loge("do_loop(): failed to connect server (%s => %s - %s:%s):"
									" errno=%d, %s \n",
									get_sockname(conn->sock),
									get_sockaddrname(&conn->raddr),
									conn->rhost,
									conn->rport,
									err, strerror(err));
								if (conn->by_proxy)
									r = on_connect_proxy_failed(conn);
								else
									r = -1;
							}
							else {
								conn->status = cs_connected;
								if (conn->by_proxy)
									r = on_proxy_connected(conn);
								else
									r = on_remote_connected(conn, 0);
							}
						}
						if (!r) {
							if (conn->proxy)
								r = proxy_write(conn);
							else
								r = handle_rwrite(conn);
						}
					}
					else if (FD_ISSET(conn->rsock, &readset)) {
						if (conn->proxy)
							r = proxy_recv(conn);
						else
							r = handle_rrecv(conn);
					}
				}

				if (!running) break;

				if (!r && conn->status == cs_closing) {
					r = -1;
					remove_dnscache(conn);
				}
				else if (!r && is_expired(conn, now)) {
					logd("connection timeout - %s%s%s%s%s%s%s\n",
						get_sockname(conn->sock),
						conn->rhost ? " => " : "",
						conn->rhost ? get_sockaddrname(&conn->raddr) : "",
						conn->rhost ? " - " : "",
						conn->rhost ? conn->rhost : "",
						conn->rhost ? ":" : "",
						conn->rport ? conn->rport : "");
					r = -1;
					if (conn->rrx == 0) {
						remove_dnscache(conn);
					}
				}

				if (r) {
					dllist_remove(&conn->entry);
					destroy_conn(conn);
					continue;
				}
			}
		}

		dnscache_check_expire(now);
	}

	return 0;
}

#ifdef WINDOWS

BOOL WINAPI sig_handler(DWORD signo)
{
	switch (signo) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		running = 0;
		break;
	default:
		break;
	}
	return TRUE;
}

static void ServiceMain(int argc, char** argv)
{
	BOOL bRet;
	bRet = TRUE;

	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandler(PROGRAM_NAME, (LPHANDLER_FUNCTION)ControlHandler);
	if (hStatus == (SERVICE_STATUS_HANDLE)0)
	{
		loge("ServiceMain(): cannot register service ctrl handler");
		return;
	}

	{
		const char* wd = win_get_exe_path();
		SetCurrentDirectory(wd);
		logn("Set working directory: %s\n", wd);
	}

	if (init_proxy_server() != 0) {
		ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		ServiceStatus.dwServiceSpecificExitCode = ERROR_SERVICE_NOT_ACTIVE;
		goto exit;
	}

	print_args();

	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &ServiceStatus);

	if (do_loop() != 0) {
		ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		ServiceStatus.dwServiceSpecificExitCode = ERROR_SERVICE_NOT_ACTIVE;
		goto exit;
	}

  exit:
	uninit_proxy_server();

	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(hStatus, &ServiceStatus);
}

static void ControlHandler(DWORD request)
{
	switch (request) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		running = 0;
		break;
	default:
		SetServiceStatus(hStatus, &ServiceStatus);
		break;
	}
}

#else

static void sig_handler(int signo) {
	if (signo == SIGINT)
		exit(1);  /* for gprof*/
	else
		running = 0;
}

#endif

static void run_as_daemonize()
{
#ifdef WINDOWS
	SERVICE_TABLE_ENTRY ServiceTable[2];

	ServiceTable[0].lpServiceName = PROGRAM_NAME;
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;

	if (!StartServiceCtrlDispatcher(ServiceTable)) {
		loge("run_as_daemonize(): cannot start service ctrl dispatcher");
	}
#else
	pid_t pid, sid;
	int dev_null;

	if (!pid_file) {
		pid_file = strdup(DEFAULT_PID_FILE);
	}

	pid = fork();
	if (pid < 0) {
		exit(1);
	}

	if (pid > 0) {
		if (pid_file) {
			FILE* file = fopen(pid_file, "w");
			if (file == NULL) {
				logc("Invalid pid file: %s\n", pid_file);
				exit(1);
			}
			fprintf(file, "%d", (int)pid);
			fclose(file);
		}
		
		exit(0);
	}

	if (init_proxy_server() != 0)
		exit(1);

	umask(0);

	if (!log_file || !(*log_file)) {
		open_syslog(PROGRAM_NAME);
	}

	sid = setsid();
	if (sid < 0) {
		exit(1);
	}

	if ((chdir("/")) < 0) {
		exit(1);
	}

	dev_null = open("/dev/null", O_WRONLY);
	if (dev_null) {
		dup2(dev_null, STDOUT_FILENO);
		dup2(dev_null, STDERR_FILENO);
	}
	else {
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	close(STDIN_FILENO);

	print_args();

	if (do_loop() != 0)
		exit(1);

	uninit_proxy_server();

#endif
}

int main(int argc, char** argv)
{
#ifdef WINDOWS
	win_init();
	log_init();
#endif

	if (parse_args(argc, argv) != 0)
		return EXIT_FAILURE;

#ifdef WINDOWS
	if (0 == SetConsoleCtrlHandler((PHANDLER_ROUTINE)sig_handler, TRUE)) {
		loge("can not set control handler\n");
		return EXIT_FAILURE;
	}
#else
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
#endif

	if (daemonize) {
		run_as_daemonize();
		return EXIT_SUCCESS;
	}

	if (init_proxy_server() != 0)
		return EXIT_FAILURE;

	print_args();

	if (do_loop() != 0)
		return EXIT_FAILURE;

	uninit_proxy_server();

	return EXIT_SUCCESS;
}
