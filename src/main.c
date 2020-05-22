#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#ifdef NDEBUG
#pragma comment(lib,"../windows/c-ares/x64/lib/cares.lib")
#else
#pragma comment(lib,"../windows/c-ares/x64/lib/caresd.lib")
#endif

#else /* else WIN64 */

#include "../windows/c-ares/x86/include/ares.h"

#ifdef NDEBUG
#pragma comment(lib,"../windows/c-ares/x86/lib/cares.lib")
#else
#pragma comment(lib,"../windows/c-ares/x86/lib/caresd.lib")
#endif

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

#define PROGRAM_NAME    "http-proxy"
#define PROGRAM_VERSION "0.0.1"

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
#define MAX_HEADER_SIZE (1024 * 1024) /* 1MB */
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

#define ERR_CREATE_SOCKET -1
#define ERR_SET_NONBLOCK  -2
#define ERR_CONNECT		  -3

#define is_eagain(err) ((err) == EAGAIN || (err) == EINPROGRESS || (err) == EWOULDBLOCK || (err) == WSAEWOULDBLOCK)

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
	int af_inet;
	int af_inet6;
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
	int addrlen;
};

typedef struct proxy_t {
	sockaddr_t addr;
	int proxy_index;
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
	int proxy_index;
	proxy_status status;
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
	int is_first_line;
	struct {
		stream_t name;
		stream_t value;
		field_status status;
	} field;
	int by_proxy;
	proxy_ctx* proxy;
	uint64_t rx; /* receive bytes */
	uint64_t tx; /* transmit bytes */
	uint64_t rrx; /* remote receive bytes */
	uint64_t rtx; /* remote transmit bytes */
#ifdef ASYN_DNS
	a_state_t* a_state;
#endif
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

static int running = 0;
static int is_use_syslog = 0;
static int is_use_logfile = 0;
static const char* current_log_file = NULL;
static listen_t listens[MAX_LISTEN] = { 0 };
static int listen_num = 0;
static dllist_t conns = DLLIST_INIT(conns);
static proxy_t proxy_list[MAX_PROXY] = { 0 };
static int proxy_num = 0;
static chnroute_ctx chnr = NULL;
static chnroute_ctx forb = NULL;
static ip_t* local_ips = NULL;
static int local_ip_cnt = 0;

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
	get_sockaddrname(&get_proxyinfo((conn)->proxy->proxy_index)->addr)

static int connect_proxy(int proxy_index, conn_t* conn);

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

static void syslog_writefile(int mask, const char* fmt, va_list args)
{
	char buf[640], buf2[1024];
	int len;
	int level = log_level_comp(mask);
	char date[32];
	const char* extra_msg;
	time_t now;

	memset(buf, 0, sizeof(buf));
	len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);

	now = time(NULL);

	strftime(date, sizeof(date), LOG_TIMEFORMAT, localtime(&now));
	extra_msg = log_priorityname(level);

	memset(buf2, 0, sizeof(buf2));

	if (extra_msg && strlen(extra_msg)) {
		len = snprintf(buf2, sizeof(buf2) - 1, "%s [%s] %s", date, extra_msg, buf);
	}
	else {
		len = snprintf(buf2, sizeof(buf2) - 1, "%s %s", date, buf);
	}

	if (len > 0) {
		FILE* pf;
		pf = fopen(current_log_file, "a+");
		if (pf) {
			fwrite(buf2, 1, len, pf);
			fclose(pf);
		}
		else {
			printf("cannot open %s\n", current_log_file);
		}
	}
}

static void syslog_vprintf(int mask, const char* fmt, va_list args)
{
#ifdef WINDOWS
	logw("syslog_vprintf(): not implemented in Windows port");
#else
	char buf[640];
	int priority = log_level_comp(mask);

	memset(buf, 0, sizeof(buf));
	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	syslog(priority, "%s", buf);
#endif
}

static void open_logfile(const char *log_file)
{
	if (log_file) {
		current_log_file = log_file;
		log_vprintf = syslog_writefile;
		log_vprintf_with_timestamp = syslog_writefile;
		is_use_logfile = 1;
	}
}

static void close_logfile()
{
	if (is_use_logfile) {
		log_vprintf = log_default_vprintf;
		log_vprintf_with_timestamp = log_default_vprintf_with_timestamp;
		is_use_logfile = 0;
	}
}

static void open_syslog()
{
#ifdef WINDOWS
	logw("use_syslog(): not implemented in Windows port");
#else
	openlog(PROGRAM_NAME, LOG_CONS | LOG_PID, LOG_DAEMON);
	is_use_syslog = 1;
	log_vprintf = syslog_vprintf;
	log_vprintf_with_timestamp = syslog_vprintf;
#endif
}

static void close_syslog()
{
#ifdef WINDOWS
	logw("close_syslog(): not implemented in Windows port");
#else
	if (is_use_syslog) {
		is_use_syslog = 0;
		log_vprintf = log_default_vprintf;
		log_vprintf_with_timestamp = log_default_vprintf_with_timestamp;
		closelog();
	}
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
	logd("a_new_state()\n");
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
		logd("a_free_state()\n");
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

static int getsockerr(sock_t sock)
{
	int err = 0, len = sizeof(int);
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

static void usage()
{
	printf("%s\n", "\n"
		PROGRAM_NAME " " PROGRAM_VERSION "\n\
\n\
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
  --proxy=SOCKS5_PROXY     Socks5 proxy, e.g. --proxy=127.0.0.1:1080\n\
                           or --proxy=[::1]:1080. More than one proxy is supported,\n\
                           in the case, if first proxy is unconnectable, it is \n\
                           automatic to switch to next proxy.\n\
                           Only socks5 with no authentication is supported.\n\
  --ipv6-prefer            IPv6 preferential.\n\
  --reverse                Reverse. If set, then connect server by proxy, \n\
                           when the server's IP in the chnroute.\n\
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
			printf(PROGRAM_NAME " %s\n", PROGRAM_VERSION);
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
	if (loglevel >= LOG_DEBUG) {
		logflags = LOG_MASK_RAW;
	}
	return 0;
}

static void print_args()
{
	int i;
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

	if (forbidden_file)
		logn("forbidden: %s\n", forbidden_file);

	if (proxy)
		logn("proxy: %s\n", proxy);

	if (ipv6_prefer)
		logn("ipv6 prefer: yes\n");

	if (dns_timeout > 0)
		logn("dns cache timeout: %d\n", dns_timeout);

	if (reverse)
		logn("reverse: yes\n");

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

#define is_true_val(s) \
   (strcmp((s), "1") == 0 || \
    strcmp((s), "on") == 0 || \
	strcmp((s), "true") == 0 || \
	strcmp((s), "yes") == 0 || \
	strcmp((s), "enabled") == 0)

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
		else {
			/*do nothing*/
		}
	}

	fclose(pf);

#undef is_true_val

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
	free(conn->proxy);
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

static int init_proxy_server()
{
	int i;

	if (log_file) {
		open_logfile(log_file);
	}
	else if (launch_log) {
		open_logfile(launch_log);
	}

	if (config_file) {
		if (read_config_file(config_file, FALSE)) {
			return -1;
		}

		if (log_file) {
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
		proxy_num = resolve_addrstr(
			proxy,
			&proxy_list[0].addr,
			MAX_PROXY,
			sizeof(proxy_t),
			"1080");
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

	if (is_use_logfile) {
		close_logfile();
	}

	if (is_use_syslog) {
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

static int get_remote_host_and_port(char** host, char** port, const conn_t* conn)
{
	if (conn->mode == pm_tunnel) {
		char* copy = strdup(conn->url.array), *h, *p;

		if (parse_addrstr(copy, &h, &p)) {
			free(copy);
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
			return -1;
		}
	}
	return 0;
}

static int get_remote_addr(sockaddr_t* addr, conn_t* conn, got_addr_callback cb)
{
	char* host, * port;
	if (get_remote_host_and_port(&host, &port, conn)) {
		loge("get_remote_addr() error: parse \"%s\" failed\n", conn->url.array);
		return -1;
	}

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
		free(host);
		free(port);
		return -1;
	}
#else
	if (host2addr(addr, host, port)) {
		loge("get_remote_addr() error: resolve \"%s:%s\" failed\n", host, port);
		free(host);
		free(port);
		return -1;
	}

	if (dns_timeout > 0) {
		if (dnscache_set(host, (char*)addr, sizeof(sockaddr_t))) {
			logw("on_got_remote_addr() error: set dns cache failed - %s\n", host);
		}
	}

	(*cb)(addr, FALSE, conn, host, port);
#endif

	free(host);
	free(port);

	return 0;
}

static int remove_dnscache(conn_t* conn)
{
	char* host, * port;

	if (dns_timeout <= 0)
		return 0;

	if (conn->mode == pm_tunnel) {
		char* copy = strdup(conn->url.array);
		if (parse_addrstr(copy, &host, &port)) {
			free(copy);
			loge("remove_dnscache() error: get 'host' from \"%s\" failed\n",
				conn->url.array);
			return -1;
		}
		if (dnscache_remove(host)) {
			logd("remove_dnscache() error: remove \"%s\" failed\n", host);
			free(copy);
			return -1;
		}
		free(copy);
		return 0;
	}
	else {
		if (get_host_and_port(&host, &port, conn->url.array, conn->url.size, 0)) {
			loge("remove_dnscache() error: get 'host' from \"%s\" failed\n", conn->url.array);
			return -1;
		}
		if (dnscache_remove(host)) {
			logd("remove_dnscache() error: remove \"%s\" failed\n", host);
			free(host);
			free(port);
			return -1;
		}
		free(host);
		free(port);
		return 0;
	}
}

static int on_remote_connected(conn_t* conn)
{
	http_parser* parser = &conn->parser;

	logd("connected %s %s\n",
		get_sockaddrname(&conn->raddr),
		conn->url.array);

	if (conn->mode == pm_tunnel) {
		if (stream_appendf(&conn->ws, "HTTP/%d.%d 200 Connection Established\r\n\r\n",
			parser->http_major,
			parser->http_minor) == -1) {
			loge("on_remote_connected() error: stream_appendf()");
			return -1;
		}
	}

	logd("\nws:\n%s\n", conn->ws.array);
	logd("\nrws:\n%s\n", conn->rws.array);

	return 0;
}

static int on_proxy_connected(conn_t* conn)
{
	stream_t* s;
	s = &conn->proxy->ws;

	if (stream_appends(s, "\x5\x1\0", 3) == -1) {
		loge("on_proxy_connected() error: stream_appends()\n");
		return -1;
	}

	conn->proxy->status = ps_handshake0;

	return 0;
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

	nsend = tcp_send(sock, s);

	if (nsend == -1)
		return -1;

	if (nsend == 0)
		return 0;

	conn->tx += nsend;

	logd("handle_write(): write to %s\n", get_sockname(sock));

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

	logd("handle_rwrite(): write to %s\n", conn->url.array);

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
	stream_reset(&conn->url);
	stream_reset(&conn->field.name);
	stream_reset(&conn->field.value);
	conn->field.status = fs_none;
	conn->is_first_line = TRUE;
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
		r = stream_appendf(&conn->rws, "%s %s HTTP/%d.%d\r\n",
			http_method_str(parser->method),
			conn->url.array,
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
		content_size = strlen(content);
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

	logi("direct connect %s - %s\n",
		get_sockaddrname(addr),
		conn->url.array);

	if (connect_addr(addr, &conn->rsock, &conn->status)) {
		return -1;
	}

	if (conn->status == cs_connected) {
		if (on_remote_connected(conn)) {
			return -1;
		}
	}

	return 0;
}

static int select_proxy(conn_t* conn)
{
	if (proxy_num > 0)
		return 0;
	return -1;
}

static int on_connect_proxy_failed(conn_t* conn)
{
	int new_proxy_index = conn->proxy->proxy_index + 1;
	if (new_proxy_index < proxy_num) {
		logd("fail connect proxy %s, switch to %s\n",
			get_conn_proxyname(conn),
			get_proxyname(new_proxy_index));
		return connect_proxy(new_proxy_index, conn);
	}
	return -1;
}

static int connect_proxy(int proxy_index, conn_t* conn)
{
	int r;

	logi("proxy connect %s - %s\n",
		get_sockaddrname(&conn->raddr),
		conn->url.array);

	conn->by_proxy = TRUE;

	if (conn->proxy) {
		stream_free(&conn->proxy->ws);
	}
	else {
		conn->proxy = (proxy_ctx*)malloc(sizeof(proxy_ctx));
		if (!conn->proxy)
			return -1;
	}

	memset(conn->proxy, 0, sizeof(proxy_ctx));

	conn->proxy->proxy_index = proxy_index;

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

static void on_got_remote_addr(sockaddr_t* addr, int hit_cache, conn_t* conn,
	const char* host, const char* port)
{
	int r;
	int proxy_index;

	if (!addr) {
		loge("on_got_remote_addr() error: get remote address failed %s\n", conn->url.array);
		close_conn(conn);
		return;
	}

	logd("on_got_remote_addr(): %s%s - %s:%s\n",
		get_sockaddrname(addr),
		hit_cache ? " (cache)" : "",
		host, port);

	if (is_forbidden(addr)) {
		logw("on_got_remote_addr() error: dead loop %s\n", conn->url.array);
		close_conn(conn);
		return;
	}

	conn->by_proxy = by_proxy(conn);

	if (conn->by_proxy && (proxy_index = select_proxy(conn)) >= 0) {
		r = connect_proxy(proxy_index, conn);
		if (r != 0) {
			logw("on_got_remote_addr() error: connect proxy failed %s\n", conn->url.array);
			close_conn(conn);
			return;
		}
	}
	else {
		r = connect_target(conn);
		if (r != 0) {
			logw("on_got_remote_addr() error: connect remote failed %s\n", conn->url.array);
			close_conn(conn);
			return;
		}
	}
}

static int connect_remote(conn_t* conn)
{
	sockaddr_t* addr = &conn->raddr;

	if (get_remote_addr(addr, conn, on_got_remote_addr)) {
		loge("connect_remote() error: get remote address failed %s\n", conn->url.array);
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

	logd("on_headers_complete(): keep_alive=%d\n", http_should_keep_alive(parser));

	if (parser->method != HTTP_CONNECT) {
		if (stream_appendf(&conn->rws, "\r\n") == -1) {
			loge("on_headers_complete() error: stream_appendf()\n");
			return -1;
		}
		conn->mode = pm_proxy;
	}
	else {
		conn->mode = pm_tunnel;
	}

	if (!conn->rsock) {
		if (connect_remote(conn))
			return -1;
	}

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
	logd("on_message_complete()\n");
	return 0;
}

static int tcp_recv(sock_t sock, char * buf, int buflen)
{
	int nread;

	nread = recv(sock, buf, buflen, 0);
	if (nread == -1) {
		int err = errno;
		if (!is_eagain(err)) {
			logi("tcp_recv() error: errno=%d, %s\n",
				err, strerror(err));
			return -1;
		}
		return 0;
	}
	else if (nread == 0) {
		logd("tcp_recv(): connection closed by peer\n");
		return -1;
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

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	conn->rx += nread;

	logd("handle_recv(): recv from %s\n", get_sockname(conn->sock));

	if (conn->mode == pm_tunnel) {
		if (stream_appends(&conn->rws, buffer, nread) == -1) {
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

static int proxy_handshake2(conn_t* conn, char* buf, int buflen)
{
	if (buflen >= 10 && buf[0] == 0x5 && buf[3] == 0x1) {
		free(conn->proxy);
		conn->proxy = NULL;
		return on_remote_connected(conn);
	}
	else {
		loge("proxy_handshake2() error: reject by proxy server\n");
		return -1;
	}
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

static int proxy_handshake1(conn_t* conn)
{
	struct sockaddr* addr = (struct sockaddr*) & conn->raddr.addr;
	stream_t* s;

	s = &conn->proxy->ws;

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in* in = (struct sockaddr_in*)addr;

		if (stream_appends(s, "\x5\x1\0\x1", 4) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, (const char*)& in->sin_addr, 4) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, sin_port_to_bytes(in->sin_port), 2) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}
	}
	else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6* in = (struct sockaddr_in6*)addr;

		if (stream_appends(s, "\x5\x1\0\x4", 4) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, (const char*)& in->sin6_addr, 16) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, sin_port_to_bytes(in->sin6_port), 2) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}
	}
	else {
		loge("proxy_handshake0() error: unknown address family\n");
		goto err;
	}

	conn->proxy->status = ps_handshake1;

	return 0;
err:
	return -1;
}

static int proxy_handshake0(conn_t* conn, char* buf, int buflen)
{
	if (buflen >= 2 && buf[0] == 0x5 && buf[1] == 0x0) {
		return proxy_handshake1(conn);
	}
	else {
		loge("proxy_handshake0() error: reject by proxy server\n");
		return -1;
	}
}

static int proxy_recv(conn_t* conn)
{
	int nread, err;
	char buffer[BUF_SIZE];

	nread = tcp_recv(conn->rsock, buffer, sizeof(buffer));

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	logd("proxy_recv(): recv from %s\n", get_conn_proxyname(conn));

	switch (conn->proxy->status) {
	case ps_handshake0:
		err = proxy_handshake0(conn, buffer, nread);
		break;
	case ps_handshake1:
		err = proxy_handshake2(conn, buffer, nread);
		break;
	default:
		err = -1;
		break;
	}

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

	if (nread == -1)
		return -1;

	if (nread == 0)
		return 0;

	conn->rrx += nread;

	logd("handle_rrecv(): recv from %s\n", conn->url.array);

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
			.tv_usec = 50 * 1000,
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
			int is_remote_connected;
			int is_remote_sending;
			int is_closing;

			dllist_foreach(&conns, cur, nxt, conn_t, conn, entry) {

				if (!running) break;

				max_fd = MAX(max_fd, conn->sock);
				is_local_sending = stream_rsize(&conn->ws) > 0;
				is_remote_connected = conn->rsock > 0 &&
					conn->status == cs_connected &&
					!conn->proxy;
				is_remote_sending = conn->rsock > 0 &&
					(conn->status == cs_connecting ||
					 (!conn->proxy && stream_rsize(&conn->rws) > 0) ||
					 (conn->proxy && stream_rsize(&conn->proxy->ws) > 0));
				is_closing = conn->status == cs_closing ||
					conn->status == cs_rsp_closing;
				if (is_local_sending)
					FD_SET(conn->sock, &writeset);
				/* read when request header is not complete,
				   or remote connection established and not sending data */
				else if(!is_closing &&
					(!conn->mode || (is_remote_connected && !is_remote_sending)))
					FD_SET(conn->sock, &readset);
				FD_SET(conn->sock, &errorset);

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
			loge("select() error: errno=%d, %s \n",
				errno, strerror(errno));
			return -1;
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

				if (FD_ISSET(conn->sock, &errorset)) {
					int err = getsockerr(conn->sock);
					loge("do_loop(): conn.sock error: errno=%d, %s \n",
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
						loge("do_loop(): conn.rsock error: errno=%d, %s \n",
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
							conn->status = cs_connected;
							if (conn->by_proxy)
								r = on_proxy_connected(conn);
							else
								r = on_remote_connected(conn);
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
					logd("connection timeout - %s\n", get_sockname(conn->sock));
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

	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &ServiceStatus);

	if (init_proxy_server() != 0)
		return;

	print_args();

	if (do_loop() != 0)
		return;

	uninit_proxy_server();

	ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	ServiceStatus.dwWin32ExitCode = 0;
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

	if (!log_file) {
		open_syslog();
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
#endif

	if (parse_args(argc, argv) != 0)
		return EXIT_FAILURE;

	if (daemonize) {
		run_as_daemonize();
		return EXIT_SUCCESS;
	}

#ifdef WINDOWS
	if (0 == SetConsoleCtrlHandler((PHANDLER_ROUTINE)sig_handler, TRUE)) {
		loge("can not set control handler\n");
		return EXIT_FAILURE;
	}
#else
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
#endif

	if (init_proxy_server() != 0)
		return EXIT_FAILURE;

	print_args();

	if (do_loop() != 0)
		return EXIT_FAILURE;

	uninit_proxy_server();

	return EXIT_SUCCESS;
}
