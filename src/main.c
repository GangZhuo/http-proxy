#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#ifdef WINDOWS
#include "../windows/win.h"
typedef SOCKET sock_t;
#else
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
typedef int sock_t;
#define strnicmp strncasecmp
#endif


#include "log.h"
#include "dllist.h"
#include "stream.h"
#include "../http-parser/http_parser.h"
#include "chnroute.h"

#define PROGRAM_NAME    "http-proxy"
#define PROGRAM_VERSION "0.0.1"

#define DEFAULT_LISTEN_ADDR "0.0.0.0"
#define DEFAULT_LISTEN_PORT "1080"
#define DEFAULT_PID_FILE "/var/run/http-proxy.pid"
#define DEFAULT_TIMEOUT 30
#define LISTEN_BACKLOG	128
#define MAX_LISTEN 8
#define BUF_SIZE 4096
#define MAX_HEADER_SIZE (1024 * 1024) /* 1MB */

#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#define _XSTR(x) #x  
#define XSTR(x) _XSTR(x)

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
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

#define is_eagain(err) ((err) == EAGAIN || (err) == EINPROGRESS || (err) == EWOULDBLOCK || (err) == WSAEWOULDBLOCK)

typedef struct sockaddr_t {
	struct sockaddr_storage addr;
	int addrlen;
} sockaddr_t;

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
	stream_t ws; /* write stream */
} proxy_ctx;

typedef struct conn_t {
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
} conn_t;

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

static int running = 0;
static int is_use_syslog = 0;
static int is_use_logfile = 0;
static const char* current_log_file = NULL;
static listen_t listens[MAX_LISTEN] = { 0 };
static int listen_num = 0;
static dllist_t conns = DLLIST_INIT(conns);
static sockaddr_t proxy_addr = { 0 };

#ifdef WINDOWS

static SERVICE_STATUS ServiceStatus = { 0 };
static SERVICE_STATUS_HANDLE hStatus = NULL;

static void ServiceMain(int argc, char** argv);
static void ControlHandler(DWORD request);
#define strdup(s) _strdup(s)

#endif

#define get_addrport(a) \
	((a)->addr.ss_family == AF_INET ? \
		((struct sockaddr_in*)(&((a)->addr)))->sin_port :\
		((struct sockaddr_in6*)(&((a)->addr)))->sin6_port)

static char* ltrim(char* s)
{
	char* p = s;
	while (p && (*p) && isspace(*p))
		p++;
	return p;
}

static char* rtrim(char* s)
{
	size_t len;
	char* p;

	len = strlen(s);
	p = s + len - 1;

	while (p >= s && isspace(*p)) (*(p--)) = '\0';

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

/* is connect self */
static int is_self(sockaddr_t *addr)
{
	int i, num = listen_num;
	listen_t* listen;

	for (i = 0; i < num; i++) {
		listen = listens + i;
		if (listen->addr.addr.ss_family == addr->addr.ss_family &&
			get_addrport(&(listen->addr)) == get_addrport(addr)) {
			
			if (addr->addr.ss_family == AF_INET) {
				struct sockaddr_in* x = (struct sockaddr_in*)(&addr->addr);
				struct sockaddr_in* y = (struct sockaddr_in*)(&listen->addr.addr);
				if (memcmp(&x->sin_addr, &y->sin_addr, 4) == 0)
					return TRUE;
			}
			else if (addr->addr.ss_family == AF_INET6) {
				struct sockaddr_in6* x = (struct sockaddr_in6*)(&addr->addr);
				struct sockaddr_in6* y = (struct sockaddr_in6*)(&listen->addr.addr);
				if (memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0)
					return TRUE;
			}
		}
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
                           e.g. -b 127.0.0.1:5354,[::1]:5354.\n\
  -p BIND_PORT             Port that listen on, default: " DEFAULT_LISTEN_PORT ".\n\
                           The port specified in \"-b\" is priority .\n\
  -t TIMEOUT               Timeout seconds, default: " XSTR(DEFAULT_TIMEOUT) ".\n\
  --daemon                 Daemonize.\n\
  --pid=PID_FILE_PATH      pid file, default: " DEFAULT_PID_FILE ", \n\
                           only available on daemonize.\n\
  --log=LOG_FILE_PATH      Write log to a file.\n\
  --log-level=LOG_LEVEL    Log level, range: [0, 7], default: " LOG_DEFAULT_LEVEL_NAME ".\n\
  --config=CONFIG_PATH     Config file, find sample at \n\
                           https://github.com/GangZhuo/http-proxy.\n\
  --chnroute=CHNROUTE_FILE Path to china route file, \n\
                           e.g.: --chnroute=lan.txt,chnroute.txt,chnroute6.txt.\n\
  --proxy=SOCKS5_PROXY     Socks5 proxy, e.g. --proxy=127.0.0.1:1080\n\
                           or --proxy=[::1]:1080.\n\
                           Only socks5 with no authentication is supported.\n\
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
		{"daemon",    no_argument,       NULL, 1},
		{"pid",       required_argument, NULL, 2},
		{"log",       required_argument, NULL, 3},
		{"log-level", required_argument, NULL, 4},
		{"config",    required_argument, NULL, 5},
		{"launch-log",required_argument, NULL, 6},
		{"proxy",     required_argument, NULL, 7},
		{"chnroute",  required_argument, NULL, 8},
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

	if (proxy)
		logn("proxy: %s\n", proxy);
}

static void parse_option(char* ln, char** option, char** name, char** value)
{
	char* p = ln;

	*option = p;
	*name = NULL;
	*value = NULL;

	while (*p && !isspace(*p)) p++;

	if (!(*p))
		return;

	*p = '\0';

	p = ltrim(p + 1);

	*name = p;

	while (*p && !isspace(*p)) p++;

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
			(ln[3] == '\0' || isspace(ln[3]))) {
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
				* port = p + 1;
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

static int host2addr(sockaddr_t* addr, const char *host, const char *port)
{
	struct addrinfo hints;
	struct addrinfo* addrinfo;
	int r;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((r = getaddrinfo(host, port, &hints, &addrinfo)) != 0) {
		loge("host2addr() error: %s %s:%s\n", gai_strerror(r), host, port);
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

static inline void update_expire(conn_t* conn)
{
	time_t t = time(NULL);
	conn->expire = t + timeout;
}

static inline int is_expired(conn_t* conn, time_t now)
{
	return conn->expire <= now;
}

static int init_proxy_server()
{
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

	if (resolve_listens() != 0)
		return -1;

	if (init_listens() != 0)
		return -1;

	if (proxy && str2addr(proxy, &proxy_addr, "1080")) {
		loge("init_proxy_server() error: invalid proxy \"%s\"\n", proxy);
		return -1;
	}

	if (chnroute) {
		if (chnroute_init()) {
			loge("init_proxy_server() error: chnroute_init()\n", proxy);
			return -1;
		}
		if (chnroute_parse(chnroute)) {
			loge("init_proxy_server() error: invalid chnroute \"%s\"\n", chnroute);
			return -1;
		}
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
	free(listen_port);
	free(pid_file);
	free(log_file);
	free(launch_log);
	free(config_file);

	if (chnroute) {
		chnroute_free();
		free(chnroute);
	}

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

static int get_remote_addr(sockaddr_t* addr, const conn_t* conn)
{
	if (conn->mode == pm_tunnel) {
		if (str2addr(conn->url.array, addr, "80")) {
			loge("get_remote_addr() error: resolve \"%s\" failed\n", conn->url.array);
			return -1;
		}
	}
	else {
		char* host, * port;
		if (get_host_and_port(&host, &port, conn->url.array, conn->url.size, 0)) {
			loge("get_remote_addr() error: parse \"%s\" failed\n", conn->url.array);
			return -1;
		}
		if (host2addr(addr, host, port)) {
			loge("get_remote_addr() error: resolve \"%s:%s\" failed\n", host, port);
			free(host);
			free(port);
			return -1;
		}
		free(host);
		free(port);
	}
	return 0;
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
		return 0;
	}
}

static int handle_write(conn_t* conn)
{
	sock_t sock = conn->sock;
	stream_t* s = &conn->ws;
	int err;

	err = tcp_send(sock, s);

	if (err)
		return -1;

	logd("handle_write(): write to %s\n", get_sockname(sock));

	update_expire(conn);

	return 0;
}

static int proxy_write(conn_t* conn)
{
	sock_t sock = conn->rsock;
	stream_t* s = &conn->proxy->ws;
	int err;

	err = tcp_send(sock, s);

	if (err)
		return -1;

	logd("proxy_write(): write to %s\n", get_sockaddrname(&proxy_addr));

	update_expire(conn);

	return 0;
}

static int handle_rwrite(conn_t* conn)
{
	sock_t sock = conn->rsock;
	stream_t* s = &conn->rws;
	int err;

	err = tcp_send(sock, s);

	if (err)
		return -1;

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
	sock_t sock;

	sock = socket(addr->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);

	if (!sock) {
		loge("connect_addr() error: create socket error. errno=%d, %s - %s\n",
			errno, strerror(errno), get_sockaddrname(addr));
		return -1;
	}

	if (setnonblock(sock) != 0) {
		loge("connect_addr() error: set sock non-block failed - %s\n",
			get_sockaddrname(addr));
		close(sock);
		return -1;
	}

	if (connect(sock, (struct sockaddr*)(&addr->addr), addr->addrlen) != 0) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("connect_addr() error: errno=%d, %s - %s\n",
				errno, strerror(errno), get_sockaddrname(addr));
			close(sock);
			return -1;
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

static int bad_request(conn_t* conn)
{
	stream_t* s = &conn->ws;
	http_parser* parser = &conn->parser;
	stream_reset(s);
	if (stream_appendf(s,
		"HTTP/%d.%d 400 Bad Request\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Connection: close\r\n"
		"Content-Length: 11\r\n"
		"\r\n"
		"Bad Request",
		parser->http_major,
		parser->http_minor) == -1) {
		loge("connect_target() error: stream_appendf()");
		return -1;
	}
	return 0;
}

static int connect_target(conn_t* conn)
{
	sockaddr_t* addr = &conn->raddr;

	logd("direct connect %s - %s\n",
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

static int connect_proxy(conn_t* conn)
{
	sockaddr_t* addr = &proxy_addr;

	logd("proxy connect %s - %s\n",
		get_sockaddrname(&conn->raddr),
		conn->url.array);

	conn->by_proxy = TRUE;
	conn->proxy = (proxy_ctx*)malloc(sizeof(proxy_ctx));
	if (!conn->proxy)
		return -1;

	memset(conn->proxy, 0, sizeof(proxy_ctx));

	if (connect_addr(addr, &conn->rsock, &conn->status)) {
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
	if (proxy == NULL || !(*proxy))
		return FALSE;

	if (chnroute) {
		struct sockaddr* addr = (struct sockaddr*)&conn->raddr.addr;
		if (chnroute_test(addr))
			return FALSE;
	}

	return TRUE;
}

static int connect_remote(conn_t* conn)
{
	int r;
	sockaddr_t* addr = &conn->raddr;

	if (get_remote_addr(addr, conn)) {
		loge("connect_remote() error: get remote address failed %s\n", conn->url.array);
		return bad_request(conn);
	}

	if (is_self(addr)) {
		return bad_request(conn);
	}

	conn->by_proxy = by_proxy(conn);

	if (conn->by_proxy)
		r = connect_proxy(conn);
	else
		r = connect_target(conn);

	return r;
}

static int on_headers_complete(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);

	logd("on_headers_complete(): keep_alive=%d\n", http_should_keep_alive(parser));

	if (conn->field.status != fs_none) {
		if (on_field_complete(parser))
			return -1;
	}
	else {
		detect_first_line_complete(parser);
	}

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
	if (stream_appends(&conn->rws, at, (int)length) == -1) {
		loge("on_body() error: stream_appends()\n");
		return -1;
	}
	return 0;
}

static int on_message_complete(http_parser* parser)
{
	conn_t* conn = dllist_container_of(parser, conn_t, parser);
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
		loge("tcp_recv() error: connection closed by peer\n");
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
			.on_chunk_header = NULL,
			.on_chunk_complete = NULL,
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
	char* host, * port;
	sockaddr_t addr;
	stream_t* s;

	if (get_host_and_port(&host, &port, conn->url.array, conn->url.size, conn->mode == pm_tunnel)) {
		loge("proxy_handshake0() error: parse \"%s\" failed\n", conn->url.array);
		return -1;
	}

	memset(&addr, 0, sizeof(sockaddr_t));

	s = &conn->proxy->ws;

	if (try_parse_as_ip(&addr, host, port)) {
		if (addr.addr.ss_family == AF_INET) {
			struct sockaddr_in* in = (struct sockaddr_in*)(&addr.addr);

			if (stream_appends(s, "\x5\x1\0\x1", 4) == -1) {
				loge("proxy_handshake0() error: stream_appends()\n");
				goto err;
			}

			if (stream_appends(s, (const char*)&in->sin_addr, 4) == -1) {
				loge("proxy_handshake0() error: stream_appends()\n");
				goto err;
			}

			if (stream_appends(s, sin_port_to_bytes(in->sin_port), 2) == -1) {
				loge("proxy_handshake0() error: stream_appends()\n");
				goto err;
			}
		}
		else if (addr.addr.ss_family == AF_INET6) {
			struct sockaddr_in6* in = (struct sockaddr_in6*)(&addr.addr);

			if (stream_appends(s, "\x5\x1\0\x4", 4) == -1) {
				loge("proxy_handshake0() error: stream_appends()\n");
				goto err;
			}

			if (stream_appends(s, (const char*)&in->sin6_addr, 16) == -1) {
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
	}
	else {
		uint8_t hostlen;
		uint16_t iport;

		if (stream_appends(s, "\x5\x1\0\x3", 4) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}

		hostlen = (uint8_t)strlen(host);

		if (stream_appends(s, &hostlen, 1) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}

		if (stream_appends(s, host, (int)hostlen) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}

		iport = htons(atoi(port));

		if (stream_appends(s, sin_port_to_bytes(iport), 2) == -1) {
			loge("proxy_handshake0() error: stream_appends()\n");
			goto err;
		}
	}

	conn->proxy->status = ps_handshake1;

	return 0;

err:
	free(host);
	free(port);
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

	logd("proxy_recv(): recv from %s\n", get_sockaddrname(&proxy_addr));

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

		max_fd = 0;

		for (i = 0; i < listen_num; i++) {
			listen_t* listen = listens + i;

			max_fd = MAX(max_fd, listen->sock);

			FD_SET(listen->sock, &readset);
			FD_SET(listen->sock, &errorset);
		}

		{
			dlitem_t* cur, * nxt;
			conn_t* conn;

			dllist_foreach(&conns, cur, nxt, conn_t, conn, entry) {
				max_fd = MAX(max_fd, conn->sock);
				if (stream_rsize(&conn->ws) > 0)
					FD_SET(conn->sock, &writeset);
				else
					FD_SET(conn->sock, &readset);
				FD_SET(conn->sock, &errorset);

				if (conn->rsock > 0) {
					max_fd = MAX(max_fd, conn->rsock);
					if (conn->status == cs_connecting ||
						(!conn->proxy && stream_rsize(&conn->rws) > 0) ||
						(conn->proxy && stream_rsize(&conn->proxy->ws) > 0))
						FD_SET(conn->rsock, &writeset);
					else
						FD_SET(conn->rsock, &readset);
					FD_SET(conn->rsock, &errorset);
				}
			}
		}

		if (select(max_fd + 1, &readset, &writeset, &errorset, &timeout) == -1) {
			loge("select() error: errno=%d, %s \n",
				errno, strerror(errno));
			return -1;
		}

		now = time(NULL);

		for (i = 0; i < listen_num; i++) {
			listen_t* listen = listens + i;

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

				if (!r && conn->rsock > 0) {
					if (FD_ISSET(conn->rsock, &errorset)) {
						int err = getsockerr(conn->rsock);
						loge("do_loop(): conn.rsock error: errno=%d, %s \n",
							err, strerror(err));
						r = -1;
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

				if (!r && is_expired(conn, now)) {
					loge("timeout - %s\n", get_sockname(conn->sock));
					r = -1;
				}

				if (r) {
					dllist_remove(&conn->entry);
					destroy_conn(conn);
					continue;
				}
			}
		}
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
}

static void ControlHandler(DWORD request)
{
	switch (request) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		running = 0;
		uninit_proxy_server();
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ServiceStatus.dwWin32ExitCode = 0;
		SetServiceStatus(hStatus, &ServiceStatus);
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
