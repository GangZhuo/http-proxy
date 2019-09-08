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
#endif


#include "log.h"
#include "dllist.h"
#include "stream.h"

#define PROGRAM_NAME    "http-proxy"
#define PROGRAM_VERSION "0.0.1"

#define DEFAULT_LISTEN_ADDR "0.0.0.0"
#define DEFAULT_LISTEN_PORT "1080"
#define DEFAULT_PID_FILE "/var/run/http-proxy.pid"
#define LISTEN_BACKLOG	128
#define MAX_LISTEN 8

#define MAX(a, b) (((a) < (b)) ? (b) : (a))

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

typedef struct conn_t {
	listen_t* listen;
	sock_t sock;
	int status;
	stream_t ws; /* write stream */
	stream_t rs; /* read stream */
	dlitem_t entry;
} conn_t;

static char* listen_addr = NULL;
static char* listen_port = NULL;
static char* pid_file = NULL;
static char* log_file = NULL;
static int daemonize = 0;
static char* launch_log = NULL;
static char* config_file = NULL;

static int running = 0;
static int is_use_syslog = 0;
static int is_use_logfile = 0;
static listen_t listens[MAX_LISTEN] = { 0 };
static int listen_num = 0;
static dllist_t conns = DLLIST_INIT(conns);

#ifdef WINDOWS

static SERVICE_STATUS ServiceStatus = { 0 };
static SERVICE_STATUS_HANDLE hStatus = NULL;

static void ServiceMain(int argc, char** argv);
static void ControlHandler(DWORD request);
#define strdup(s) _strdup(s)

#endif

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
		pf = fopen(log_file, "a+");
		if (pf) {
			fwrite(buf2, 1, len, pf);
			fclose(pf);
		}
		else {
			printf("cannot open %s\n", log_file);
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

static void open_logfile()
{
	if (log_file) {
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

static int is_ipv6(const char* ip)
{
	return !!strchr(ip, ':');
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

static void usage()
{
  printf("%s\n", "\n"
PROGRAM_NAME " " PROGRAM_VERSION "\n\
\n\
Usage:\n\
\n\
http-proxy [-b BIND_ADDR] [-p BIND_PORT] [--config=CONFIG_PATH] [--daemon] [--pid=PID_FILE_PATH]\n\
         [--log=LOG_FILE_PATH] [--log-level=LOG_LEVEL] [-v] [-V] [-h]\n\
\n\
Http proxy.\n\
\n\
Options:\n\
\n\
  -b BIND_ADDR          Address that listens, default: " DEFAULT_LISTEN_ADDR ".\n\
                        Use comma to separate multi addresses, e.g. 127.0.0.1:5354,[::1]:5354.\n\
  -p BIND_PORT          Port that listen on, default: " DEFAULT_LISTEN_PORT ".\n\
                        The port specified in \"-b\" is priority .\n\
  --daemon              Daemonize.\n\
  --pid=PID_FILE_PATH   pid file, default: " DEFAULT_PID_FILE ", only available on daemonize.\n\
  --log=LOG_FILE_PATH   Write log to a file.\n\
  --log-level=LOG_LEVEL Log level, range: [0, 7], default: " LOG_DEFAULT_LEVEL_NAME ".\n\
  --config=CONFIG_PATH  Config file, find sample at https://github.com/GangZhuo/http-proxy.\n\
  -v                    Verbose logging.\n\
  -h                    Show this help message and exit.\n\
  -V                    Print version and then exit.\n\
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
		{"launch_log",required_argument, NULL, 6},
		{0, 0, 0, 0}
	};

	while ((ch = getopt_long(argc, argv, "hb:p:vV", long_options, &option_index)) != -1) {
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
		case 'h':
			usage();
			exit(0);
		case 'b':
			listen_addr = strdup(optarg);
			break;
		case 'p':
			listen_port = strdup(optarg);
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

static int str2addr(
	char* s, sockaddr_t* addr,
	const char* default_port)
{
	char* host, * port;
	struct addrinfo hints;
	struct addrinfo* addrinfo;
	int r;

	if (parse_addrstr(s, &host, &port))
		return -1;

	if (!port || strlen(port) == 0)
		port = (char*)default_port;

	if (!port || strlen(port) == 0)
		port = DEFAULT_LISTEN_PORT;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = is_ipv6(host) ? AF_INET6 : AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((r = getaddrinfo(host, port, &hints, &addrinfo)) != 0) {
		loge("str2addr() error: %s %s:%s\n", gai_strerror(r), port, port);
		return -1;
	}

	memcpy(&addr->addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
	addr->addrlen = addrinfo->ai_addrlen;

	freeaddrinfo(addrinfo);

	return 0;
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

	memset(conn, 0, sizeof(conn));

	conn->sock = sock;
	conn->listen = listen;

	if (stream_init(&conn->ws)) {
		loge("new_conn() error: stream_init() error.");
		free(conn);
		return NULL;
	}

	if (stream_init(&conn->rs)) {
		loge("new_conn() error: stream_init() error.");
		free(conn);
		return NULL;
	}

	return conn;
}

static void free_conn(conn_t* conn)
{
	if (conn == NULL)
		return;
	if (conn->sock)
		close(conn->sock);
	stream_free(&conn->ws);
	stream_free(&conn->rs);
}

static void destroy_conn(conn_t* conn)
{
	free_conn(conn);
	free(conn);
}

static int init_proxy_server()
{
	if (log_file) {
		open_logfile();
	}
	else if (launch_log) {
		log_file = launch_log;
		launch_log = NULL;
		open_logfile();
	}

	if (config_file) {
		if (read_config_file(config_file, FALSE)) {
			return -1;
		}

		if (log_file) {
			open_logfile();
		}
	}

	if (check_args())
		return -1;

	if (resolve_listens() != 0)
		return -1;

	if (init_listens() != 0)
		return -1;

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

	{
		dlitem_t* cur, * nxt;
		conn_t* conn;

		dllist_foreach(&conns, cur, nxt, conn_t, conn, entry) {
			destroy_conn(conn);
		}
	}

	if (log_file) {
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

	return 0;
}

static int handle_write(conn_t* conn)
{
	stream_t* s = &conn->ws;
	int rsize = stream_rsize(s);
	int nsend;

	nsend = send(conn->sock, s->array + s->pos, rsize, 0);
	if (nsend == -1) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("handle_write() error: errno=%d, %s \n",
				err, strerror(err));
			dllist_remove(&conn->entry);
			destroy_conn(conn);
			return -1;
		}
		return 0;
	}
	else {
		s->pos += nsend;
		stream_shrink(s);
		logd("send %d bytes\n", nsend);
		return 0;
	}
}

static int handle_recv(conn_t* conn)
{
	stream_t* s = &conn->rs;
	int nread;
	char buffer[4096];

	nread = recv(conn->sock, buffer, sizeof(buffer), 0);
	if (nread == -1) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("handle_recv() error: errno=%d, %s\n",
				err, strerror(err));
			dllist_remove(&conn->entry);
			destroy_conn(conn);
			return -1;
		}
		return 0;
	}
	else if (nread == 0) {
		loge("handle_recv() error: connection closed by peer\n");
		dllist_remove(&conn->entry);
		destroy_conn(conn);
		return -1;
	}
	else {
		stream_write(s, buffer, nread);
		stream_writei8(s, 0);
		s->pos--;
		logd("handle_recv(): %s\n", s->array);
		return 0;
	}
}

static int do_loop()
{
	fd_set readset, writeset, errorset;
	sock_t max_fd;
	int i;

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
			}
		}

		if (select(max_fd + 1, &readset, &writeset, &errorset, &timeout) == -1) {
			loge("select() error: errno=%d, %s \n",
				errno, strerror(errno));
			return -1;
		}

		for (i = 0; i < listen_num; i++) {
			listen_t* listen = listens + i;

			if (FD_ISSET(listen->sock, &errorset)) {
				loge("do_loop(): listen.sock error\n");
				return -1;
			}

			if (FD_ISSET(listen->sock, &readset)) {
				handle_accept(listen);
			}
		}

		{
			dlitem_t* cur, * nxt;
			conn_t* conn;

			dllist_foreach(&conns, cur, nxt, conn_t, conn, entry) {
				if (FD_ISSET(conn->sock, &errorset)) {
					loge("do_loop(): conn.sock error\n");
					return -1;
				}

				if (FD_ISSET(conn->sock, &writeset)) {
					handle_write(conn);
				}

				if (FD_ISSET(conn->sock, &readset)) {
					handle_recv(conn);
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

	if (!cleandns->pid_file) {
		cleandns->pid_file = strdup(DEFAULT_PID_FILE);
	}

	pid = fork();
	if (pid < 0) {
		exit(1);
	}

	if (pid > 0) {
		if (cleandns->pid_file) {
			FILE* file = fopen(cleandns->pid_file, "w");
			if (file == NULL) {
				logc("Invalid pid file: %s\n", cleandns->pid_file);
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
