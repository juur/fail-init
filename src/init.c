#define _XOPEN_SOURCE 700

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <time.h>
#include <unistd.h>

#define __USE_MISC
#include <syslog.h>
#undef  __USE_MISC

#include "config.h"

/* enum definitions */

enum actions {
	ACT_RESPAWN,
	ACT_WAIT,
	ACT_ONCE,
	ACT_BOOT,
	ACT_BOOTWAIT,
	ACT_OFF,
	ACT_ONDEMAND,
	ACT_INITDEFAULT,
	ACT_SYSINIT,
	ACT_POWERWAIT,
	ACT_POWERFAIL,
	ACT_POWEROKWAIT,
	ACT_POWERFAILNOW,
	ACT_CTRLALTDEL,
	ACT_KBRREQUEST
};

#define RUNLEVEL_0 (1 << 0)
#define RUNLEVEL_1 (1 << 1)
#define RUNLEVEL_2 (1 << 2)
#define RUNLEVEL_3 (1 << 3)
#define RUNLEVEL_4 (1 << 4)
#define RUNLEVEL_5 (1 << 5)
#define RUNLEVEL_6 (1 << 6)
#define RUNLEVEL_7 (1 << 7)
#define RUNLEVEL_8 (1 << 8)
#define RUNLEVEL_9 (1 << 9)

#define RUNLEVEL_S (1 << 10)

#define RUNLEVEL_A (1 << 11)
#define RUNLEVEL_B (1 << 12)
#define RUNLEVEL_C (1 << 13)

#define PIPE_NAME	"/run/initctl"

/* structure and type defintions (and tightly coupled defines) */

struct entry {
	const char *	id;
	const char *	process;
	enum actions	action;

	long	runlevels;
	bool	wait;
	bool	no_utmp;

	pid_t	pid;
	time_t	next_run;
	int		con_type;
};

struct init_request {
	int32_t	magic;
	int32_t	cmd;
	int32_t	runlevel;
	int32_t	sleeptime;
	int8_t	data[368];
} __attribute__ ((packed));

#define INIT_REQ_MAGIC	0x03091969

#define CMD_SET_RUNLVL		1
#define CMD_PWR_FAILSOON	2
#define CMD_PWR_FAILNOW		3
#define CMD_PWR_OK			4
#define CMD_SET_ENVP		6

struct act_name {
	const char *name;
	const enum actions action;
};

/* private constant declarations */

static const struct act_name act_names[] = {
	{ "respawn",		ACT_RESPAWN			},
	{ "wait",			ACT_WAIT			},
	{ "once",			ACT_ONCE			},
	{ "boot",			ACT_BOOT			},
	{ "bootwait",		ACT_BOOTWAIT		},
	{ "off",			ACT_OFF				},
	{ "ondemand",		ACT_ONDEMAND		},
	{ "initdefault",	ACT_INITDEFAULT		},
	{ "sysinit",		ACT_SYSINIT			},
	{ "powerwait",		ACT_POWERWAIT		},
	{ "powerfail",		ACT_POWERFAIL		},
	{ "powerokwait",	ACT_POWEROKWAIT		},
	{ "powerfailnow",	ACT_POWERFAILNOW	},
	{ "ctrlaltdel",		ACT_CTRLALTDEL		},
	{ "kbrrequest",		ACT_KBRREQUEST		},
	
	{NULL,0}
};

static const char *const cfg_regex = 
	"^(.{1,4}):([a-zA-Z0-9]*):([a-z]+):([+]?)(.*)$";

/* private variables */

static regex_t		cfg_regcomp;
static regmatch_t	cfg_regmatch[6]; /* cfg_regex matches */

static int old_mask;

static int opt_auto			= 0;
static int opt_emerg		= 0;
static int opt_def_runlevel = -1;

static int pipe_fd			= -1;

static char run_level_id		= '\0';
static long run_level			= -1;
static long old_level			= -1;

static struct entry *entries	= NULL;
static int num_entries			= 0;

static const char *opt_cfg_filename	= "/etc/inittab";
static const int cfg_regnmatch		= sizeof(cfg_regmatch) / sizeof(regmatch_t);

/* private function defintions */

static void errx(int eval, const char *const fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	exit(eval);
}

static void err(int eval, const char *const fmt, ...)
{
	const int save_err = errno;
	va_list ap;
	
	va_start(ap, fmt);
	const int len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	char *newfmt = malloc(len + 1);

	if( !newfmt ) {
		perror("init: err");
		errx(EXIT_FAILURE, "unable to malloc within err");
	}

	va_start(ap, fmt);
	vsnprintf(newfmt, len + 1, fmt, ap);
	va_end(ap);

	syslog(LOG_ERR, "%s: %s", newfmt, strerror(save_err));
	free(newfmt);

	exit(eval);
}


static void warn(const char *const fmt, ...)
{
	int save_err = errno;
	va_list ap;
	
	va_start(ap, fmt);
	const int len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	char *newfmt = malloc(len + 1);

	if( !newfmt ) {
		perror("init: warn");
		errx(EXIT_FAILURE, "unable to malloc within warn");
	}

	va_start(ap, fmt);
	vsnprintf(newfmt, len + 1, fmt, ap);
	va_end(ap);

	syslog(LOG_WARNING, "%s: %s", newfmt, strerror(save_err));

	free(newfmt);
}

static void warnx(const char *const fmt, ...)
{
	va_list ap;
	
	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
}


static int get_runlevel(const char c)
{
	if( c >= '0' && c <= '9' )
		return (1 << (c - '0'));
	else if( c == 's')
		return RUNLEVEL_S;
	else if( c >= 'a' && c <= 'c' )
		return (1 << (11 - (c - 'a')));
	return -1;
}

static enum actions string_to_action(const char *const str)
{
	for( int i = 0; act_names[i].name; i++ )
		if( !strcmp(str, act_names[i].name) )
			return act_names[i].action;

	return -1;	
}

static bool is_valid_runlevel(const char c)
{
	if( (c >= '0' && c <= '9') || 
			c == 's' || 
			(c >= 'a' && c <= 'c')) return true;
	return false;
}

static void trim(char *str)
{
	for( char *ptr = str + strlen(str) - 1; 
			ptr >= str && isspace(*ptr); *(ptr--) = '\0' ) ;
}

static char **split(const char *text, const char *delim)
{
	int count = 0, retlen;
	const char *tmp = text;
	char *str;
	char **ret, *saveptr;

	while( (tmp = strstr(tmp+1, delim)) != NULL ) 
		count++;

	retlen = count + 2;

	if( (ret = calloc(retlen, sizeof(char *))) == NULL) {
		warn("unable to process '%s'", text);
		goto split_err0;
	}

	if( (str = strdup(text)) == NULL ) {
		warn("unable to process '%s'", text);
		goto split_err1;
	}

	tmp = strtok_r(str, delim, &saveptr);
	count = 0;

	while( tmp )
	{
		if( strlen(tmp) ) {
			if( (ret[count++] = strdup(tmp)) == NULL ) {
				warn("unable to process '%s'", text);
				goto split_err3;
			}
		}
		tmp = strtok_r(NULL, delim, &saveptr);
	}

	free(str);
	return ret;

split_err3:
	for( int i = 0; i < retlen; i++ ) {
		if( ret[i] ) free(ret[i]);
	}
	free(ret);
	free(str);

split_err1:
	free(ret);

split_err0:
	return NULL;
}

static void read_config(void)
{
	FILE *cfg = NULL;
	char buf[BUFSIZ], *tmp;
	int line = -1;
	char *id = NULL, *runlevels = NULL, *action_name = NULL, *process = NULL;
	bool no_utmp = 0;
	int action;
	
	if( (cfg = fopen(opt_cfg_filename, "r")) == NULL )
		err(EXIT_FAILURE, "unable to open inittab '%s'", opt_cfg_filename);

	if( regcomp(&cfg_regcomp, cfg_regex, REG_EXTENDED) )
		errx(EXIT_FAILURE, "unable to compile inittab regex");

	for(;;)
	{
		if( feof(cfg) )
			break;

		if( ferror(cfg) ) {
			warnx("error whilst reading inittab around line %d", line + 1);
			break;
		}

		if( (tmp = fgets(buf, sizeof(buf), cfg)) == NULL )
			break;

		line++;

		if( strlen(tmp) <= 1 )
			continue;

		while( *tmp && isspace(*tmp) ) tmp++;

		if( !*tmp )
			continue;

		if( *tmp == '#' )
			continue;

		if( regexec(&cfg_regcomp, buf, cfg_regnmatch, cfg_regmatch, 0) 
				== REG_NOMATCH ) {
			warnx("invalid line %d", line);
			puts(buf);
			continue;
		}

		if (cfg_regmatch[1].rm_so != -1)
			id = strndup(buf + cfg_regmatch[1].rm_so,
					cfg_regmatch[1].rm_eo - cfg_regmatch[1].rm_so);

		if (cfg_regmatch[2].rm_so != -1)
			runlevels = strndup(buf + cfg_regmatch[2].rm_so,
					cfg_regmatch[2].rm_eo - cfg_regmatch[2].rm_so);

		if (cfg_regmatch[3].rm_so != -1)
			action_name = strndup(buf + cfg_regmatch[3].rm_so,
					cfg_regmatch[3].rm_eo - cfg_regmatch[3].rm_so);

		no_utmp = (cfg_regmatch[4].rm_so != -1);

		if (cfg_regmatch[5].rm_so != -1)
			process = strndup(buf + cfg_regmatch[5].rm_so,
					cfg_regmatch[5].rm_eo - cfg_regmatch[5].rm_so);

		trim(process);

		if( (action = string_to_action(action_name)) == -1 ) {
			warnx("invalid action '%s' on line %d", action_name, line);
			goto parse_skip;
		}

		bool skip = false;

		if( strlen(runlevels) )
			for( int i = 0; runlevels[i]; i++ ) {
				runlevels[i] = tolower(runlevels[i]);
				if( !is_valid_runlevel(runlevels[i]) ) {
					warnx("invalid runlevel '%c' on line %d", 
							runlevels[i], line);
					skip = true;
				}
			}

		if( skip )
			goto parse_skip;

		switch( action )
		{
			case ACT_INITDEFAULT:
				/* TODO: check runlevels is an integer */
				if (opt_def_runlevel == -1)
					opt_def_runlevel = *runlevels;
				skip = true;
				break;
			default:
				break;
		}

		if( skip )
			goto parse_skip;

		int ent_id = num_entries;

		if( (entries = realloc(entries, 
						sizeof(struct entry) * ++num_entries)) == NULL ) {
			warn("unable to allocate memory for line %d", line);
			goto parse_skip;
		}

		memset(&entries[ent_id], 0, sizeof(struct entry));

		entries[ent_id].id = id;
		
		for( int i = 0; runlevels[i]; i++ )
			entries[ent_id].runlevels |= get_runlevel(runlevels[i]);
		
		if( entries[ent_id].runlevels & RUNLEVEL_S )
			entries[ent_id].con_type = 1;

		entries[ent_id].action = action;
		entries[ent_id].process = process;
		entries[ent_id].no_utmp = no_utmp;

		continue;

parse_skip:
		if( id ) {			free(id);			id			= NULL; }
		if( runlevels ) {	free(runlevels);	runlevels	= NULL; }
		if( action_name ) {	free(action_name);	action_name	= NULL; }
		if( process ) {		free(process);		process		= NULL; }
		continue;
	}

}

static void parse_command_line(int argc, char *argv[])
{
	char opt;

	while( (opt = getopt(argc, argv, "absz:f:")) != -1)
	{
		switch( opt )
		{
			case 'a':
				opt_auto = 1;
				break;
			case 'b':
				opt_emerg = 1;
				break;
			case 'f':
				/* FIXME handle duplicate -f */
				opt_cfg_filename = strdup(optarg);
				break;
			case 's':
				opt_def_runlevel = 's';
				break;
			case 'z':
				break;
			default:
				warnx("unknown command line option '%c'", opt);
				break;
		}
	}

	/* TODO: check for 'auto' and 'single' */

	if( optind - argc > 1 ) {
		warnx("invalid arguments passed");
	} else if( argc - optind == 1) {
		const char rl = *argv[argc-1];
		if( is_valid_runlevel(rl) )
			opt_def_runlevel = rl;
		else
			warnx("invalid runlevel '%c' as argument", rl);
	}
}

static void sighup_handler(int sig)
{
	syslog(LOG_NOTICE, "received SIGHUP, reloading configuration file");
}

static void sigusr1_handler(int sig)
{
	syslog(LOG_NOTICE, "received SIGUSR1");
}

static void sigusr2_handler(int sig)
{
	syslog(LOG_NOTICE, "received SIGUSR2");
}

static void sigint_handler(int sig)
{
	syslog(LOG_NOTICE, "received SIGINT, CTRL-ALT-DEL pressed");
	exit(EXIT_SUCCESS);
}

static void sigwinch_handler(int sig)
{
	syslog(LOG_NOTICE, "received SIGWINCH, KeyboarSignal pressed");
}

static void sigpwr_handler(int sig)
{
	syslog(LOG_NOTICE, "received SIGPWR");
}

static void chld_handler(int sig)
{
	int wstatus;
	pid_t pid;

	syslog(LOG_INFO, "child handler invoked");

	while( (pid = waitpid(-1, &wstatus, WNOHANG)) != 0 )
	{
		if( pid == -1 && errno == ECHILD )
			break;
		else if( pid == -1 ) {
			warn("chld_handler: waitpid");
			continue;
		}

		syslog(LOG_INFO, "child handler checking PID %d exited=%d rc=%d", pid,
				WIFEXITED(wstatus), WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : 0);

		for( int i = 0; i < num_entries; i++ ) {
			if( entries[i].pid == pid ) {
				entries[i].pid = 0;
				if( !WIFEXITED(wstatus) || WEXITSTATUS(wstatus) )
					entries[i].next_run = time(NULL) + 2;
				else
					entries[i].next_run = 0;
			}
		}
	}
}

static const char *const def_envp[] = {
	"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
	"INIT_VERSION=" VERSION,
	"CONSOLE=/dev/console",
};

static const int def_envp_len = sizeof(def_envp)/sizeof(char *);

static void execute_child(const char *const cmdline, const int con_type)
{
	char **argv = split(cmdline, " ");
	char **envp;
	sigset_t sigset;
	int con_fd;

	sigfillset(&sigset);
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);

	if( argv == NULL || argv[0] == NULL )
		errx(EXIT_FAILURE, "no args for '%s'", cmdline);

	if( (envp = calloc(def_envp_len + 4, sizeof(char *))) == NULL )
		err(EXIT_FAILURE, "cannot allocate envp for '%s'", cmdline);

	for( int i = 0; i < def_envp_len; i++ )
		envp[i] = strdup(def_envp[i]);

	envp[def_envp_len] = strdup("RUNLEVEL=x");
	envp[def_envp_len+1] = strdup("PREVLEVEL=x");

	close(0);
	close(1);
	close(2);

	const char *con_name = con_type ? "/dev/null" : "/dev/console";

	if( (con_fd = open(con_name, O_RDWR|O_NOCTTY)) == -1 )
		exit(EXIT_FAILURE);

	if( dup(con_fd) == -1 || dup(con_fd) == -1 )
		warn("dup in execute_child");

	setsid();

	umask(old_mask);

	if( execve(argv[0], argv, envp) )
		err(EXIT_FAILURE, "unable to execv '%s' for '%s'", argv[0], cmdline);
}

static void run_nowait(struct entry *ent)
{
	pid_t child_pid;

	if( ent->next_run && ent->next_run > time(NULL) )
		return;

	if( (ent->pid = child_pid = fork()) ) {
		return;
	}

	execute_child(ent->process, ent->con_type);
}

static void run_wait(struct entry *ent)
{
	pid_t child_pid;
	int wstatus;
	time_t t;

	if( ent->next_run && ent->next_run > (t = time(NULL)) )
		sleep(ent->next_run - t);

	if( (ent->pid = child_pid = fork()) ) {
		waitpid(child_pid, &wstatus, 0);
		ent->pid = 0;
		return;
	}

	execute_child(ent->process, ent->con_type);
}

static inline void close_pipe(void)
{
	close(pipe_fd);
	pipe_fd = -1;
}

static int check_pipe(void)
{
	struct stat st;

	if( stat(PIPE_NAME, &st) == -1 && errno == ENOENT ) {
		
		if( pipe_fd != -1)
			close_pipe();

		if( mkfifo(PIPE_NAME, 0600) == -1 )
			warn("mkfifo failed");
	}

	/* TODO check if inode has changed? */

	if( pipe_fd == -1 )
		if( (pipe_fd = open(PIPE_NAME, O_RDWR|O_NONBLOCK)) == -1 )
			warn("unable to open initctl");

	return pipe_fd;
}

static void change_run_level(const int old, const int new_level)
{
	const int sigs[] = { SIGTERM, SIGKILL };

	syslog(LOG_NOTICE, "entering runlevel '%c'", run_level_id);

	for( int sig = 0; sig < 2; sig++) {
		for( int i = 0; i < num_entries; i++ )
			if( entries[i].action == ACT_RESPAWN && !(entries[i].runlevels & old) && entries[i].pid != 0)
				kill(entries[i].pid, sigs[sig]);
		sleep(3);
	}

	/* TODO: 
	 * make initctl work
	 */

	old_level = old;

	run_level = new_level;
	run_level_id = get_runlevel(run_level);

	for( int i = 0; i < num_entries; i++ )
		if( entries[i].action == ACT_ONCE && (entries[i].runlevels & run_level) )
			run_nowait(&entries[i]);

	for( int i = 0; i < num_entries; i++ )
		if( entries[i].action == ACT_WAIT && (entries[i].runlevels & run_level) )
			run_wait(&entries[i]);

	for( int i = 0; i < num_entries; i++ )
		if( entries[i].action == ACT_RESPAWN && (entries[i].runlevels & run_level) && entries[i].pid == 0 )
			run_nowait(&entries[i]);

	if( new_level == 's' ) {
		for( int i = 0; i < num_entries; i++ )
			if( (entries[i].runlevels & RUNLEVEL_S) ) {
				run_wait(&entries[i]);
				break;
			}
	}
}

static void process_pipe(int fd)
{
	struct init_request req;
	ssize_t len;

	while(true)
	{
		len = read(fd, &req, sizeof(struct init_request));

		if( len == 0 || (len == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) ) {
			return;
		} else if( len == -1 ) {
			close_pipe();
			return;
		} else if( len != sizeof(struct init_request) ) {
			warnx("invalid packet on initctl");
		} else if( req.magic != INIT_REQ_MAGIC ) {
			warnx("invalid magic on initctl");
		} else {
			switch(req.cmd)
			{
				case CMD_SET_RUNLVL:
					/* FIXME: convert req.run_level !!! */
					change_run_level(run_level, req.runlevel);
					break;
				default:
					warnx("unknown or unsupported command '%d' on initctl", req.cmd);
					break;
			}
		}
	}
}

static void main_loop(void)
{
	fd_set read_set, ex_set;
	struct timeval tv;

	/* TODO:
	 * process initctl
	 */

	while(true)
	{
		const int fd = check_pipe();

		if( fd == -1 ) {
			sleep(10);
		} else {

			FD_SET(fd, &read_set);
			FD_SET(fd, &ex_set);

			tv = (struct timeval) {
				.tv_sec  = 5,
				.tv_usec = 0
			};

			const int ret = select(fd + 1, &read_set, NULL, &ex_set, &tv);

			if( ret < 0 && errno != EINTR ) {
				warn("select on initctl");
				close_pipe();
			} else if( ret > 1 ) {
				if( FD_ISSET(fd, &ex_set) ) {
					close_pipe();
				} else if( FD_ISSET(fd, &read_set) ) {
					process_pipe(fd);
				}
			}

		} /* if( fd == -1 ) */

		for( int i = 0; i < num_entries; i++ )
			if( !entries[i].pid && (entries[i].runlevels & run_level) && entries[i].action == ACT_RESPAWN )
				run_nowait(&entries[i]);
	} /* while(true) */
}

struct mount_ent {
	const char *const source;
	const char *const dest;
	const char *const fstype;
	const int flags;
	const char *const data;
};

static const struct mount_ent mount_ents[] = {
	{ "devtmpfs",	"/dev",		"devtmpfs",	MS_NOEXEC|MS_NOSUID|MS_RELATIME,			"gid=5,mode=620,ptmxmode=000" },
	{ "sys",		"/sys",		"sysfs",	MS_NODEV|MS_NOEXEC|MS_NOSUID|MS_RELATIME,	NULL },
	{ "proc",		"/proc",	"proc",		MS_NODEV|MS_NOEXEC|MS_NOSUID|MS_RELATIME,	NULL }
};
static int num_mount_ents = sizeof(mount_ents) / sizeof(struct mount_ent);

/* public function definitions */

int main(int argc, char *argv[], char *envp[])
{
	sigset_t set, all_block;
	int con_fd;
	//int status;
	const pid_t my_pid = getpid();
	//const bool istty = isatty(fileno(stderr));
	struct stat sb;

	old_mask = umask(0);

	openlog("init", LOG_CONS|LOG_PID, LOG_DAEMON);
	syslog(LOG_NOTICE, "init starting");

	if( getuid() != 0 || geteuid() != 0 )
		warnx("must be ran as root");

	if( my_pid != 1 )
		warnx("must be PID 1");

	for( int i = 0; i < num_mount_ents; i++ )
		if( !stat(mount_ents[i].dest, &sb) )
			if( mount(mount_ents[i].source, mount_ents[i].dest, 
					mount_ents[i].fstype, mount_ents[i].flags,
					mount_ents[i].data) == -1 && errno != EBUSY )
				warn("mount %s", mount_ents[i].dest);

	for( int i = 0; envp[i]; i++ )
		printf(" %s\n", envp[i]);
	
	if( (con_fd = open("/dev/tty", O_RDWR|O_NOCTTY)) != -1 )
		ioctl(con_fd, TIOCNOTTY);

	if( setsid() == -1 )
		warn("unable to setsid()");

	close(0);
	close(1);
	close(2);

	if( (con_fd = open("/dev/null", O_RDWR|O_NOCTTY)) == -1 )
		warn("/dev/null");

	if( dup(con_fd) == -1 || dup(con_fd) == -1 )
		warn("dup in main");

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if( chdir("/") == -1 )
		warn("unable to chdir to /");

	parse_command_line(argc, argv);

	sigfillset(&set);
	sigfillset(&all_block);
	sigprocmask(SIG_BLOCK, &set, 0);
	sigprocmask(SIG_BLOCK, &all_block, 0);

	read_config();

	run_level_id = opt_def_runlevel;
	run_level = get_runlevel(run_level_id);

	if( run_level == -1 ) {
		warnx("no runlevel specified on command line or inittab");
		run_level_id = 's';
		run_level = RUNLEVEL_S;
	}

	if( sigaction(SIGCHLD, &(const struct sigaction) {
				.sa_handler = chld_handler,
				.sa_flags = SA_NOCLDSTOP,
				.sa_mask = all_block
				}, NULL) )
		err(EXIT_FAILURE, "failure on sigaction(SIGCHLD)");

	sigprocmask(SIG_UNBLOCK, &set, 0);

	if( sigaction(SIGHUP, &(const struct sigaction) { .sa_handler = sighup_handler}, NULL) )
		err(EXIT_FAILURE, "failure on sigaction(SIGHUP)");
	if( sigaction(SIGUSR1, &(const struct sigaction) { .sa_handler = sigusr1_handler}, NULL) )
		err(EXIT_FAILURE, "failure on sigaction(SIGUSR1)");
	if( sigaction(SIGUSR2, &(const struct sigaction) { .sa_handler = sigusr2_handler}, NULL) )
		err(EXIT_FAILURE, "failure on sigaction(SIGUSR2)");
	if( sigaction(SIGINT, &(const struct sigaction) { .sa_handler = sigint_handler}, NULL) )
		err(EXIT_FAILURE, "failure on sigaction(SIGINT)");
	if( sigaction(SIGWINCH, &(const struct sigaction) { .sa_handler = sigwinch_handler}, NULL) )
		err(EXIT_FAILURE, "failure on sigaction(SIGWINCH)");
	if( sigaction(SIGPWR, &(const struct sigaction) { .sa_handler = sigpwr_handler}, NULL) )
		err(EXIT_FAILURE, "failure on sigaction(SIGPWR)");

	for( int i = 0; i < num_entries; i++ )
		if( entries[i].action == ACT_SYSINIT )
			run_wait(&entries[i]);

	for( int i = 0; i < num_entries; i++ )
		if( entries[i].action == ACT_BOOT )
			run_nowait(&entries[i]);

	for( int i = 0; i < num_entries; i++ )
		if( entries[i].action == ACT_BOOTWAIT )
			run_wait(&entries[i]);

	change_run_level(0, run_level_id);

	main_loop();
}
