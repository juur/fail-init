#define _XOPEN_SOURCE 700

#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <regex.h>
#include <errno.h>

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

/* structure and type defintions */

struct entry {
	const char *	id;
	const char *	runlevels;
	const char *	process;
	enum actions	action;

	bool	wait;
	bool	no_utmp;

	pid_t	pid;
};

struct act_name {
	const char *name;
	enum actions action;
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

static int opt_auto			= 0;
static int opt_emerg		= 0;
static int opt_def_runlevel = -1;

static int run_level		= -1;

static struct entry *entries	= NULL;
static int num_entries			= 0;

static const char *opt_cfg_filename	= "/etc/inittab";
static const int cfg_regnmatch		= sizeof(cfg_regmatch) / sizeof(regmatch_t);

/* private function defintions */

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

	while( (tmp = strstr(tmp, delim)) != NULL ) 
		count++;

	if( count == 0 )
		goto split_err0;

	retlen = count + 1;

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
		if( id ) {			free(id);			id			= NULL; }
		if( runlevels ) {	free(runlevels);	runlevels	= NULL; }
		if( action_name ) {	free(action_name);	action_name	= NULL; }
		if( process ) {		free(process);		process		= NULL; }

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
			continue;
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
			continue;

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
			continue;

		int ent_id = num_entries;

		if( (entries = realloc(entries, 
						sizeof(struct entry) * ++num_entries)) == NULL ) {
			warn("unable to allocate memory for line %d", line);
			continue;
		}

		memset(&entries[ent_id], 0, sizeof(struct entry));

		entries[ent_id].id = id;
		entries[ent_id].runlevels = runlevels;
		entries[ent_id].action = action;
		entries[ent_id].process = process;
		entries[ent_id].no_utmp = no_utmp;

		printf("DEBUG: added entry %s:%s:%s:%s\n", 
				id, runlevels, action_name, process);
	}

	if( id ) {			free(id);			id			= NULL; }
	if( runlevels ) {	free(runlevels);	runlevels	= NULL; }
	if( action_name ) {	free(action_name);	action_name	= NULL; }
	if( process ) {		free(process);		process		= NULL; }
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

	printf("DEBUG: optind=%d, argc=%d\n", optind, argc);

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

static void chld_handler(int sig)
{
	int wstatus;
	pid_t pid;

	while( (pid = waitpid(-1, &wstatus, WNOHANG)) != 0 )
	{
		if( errno == ECHILD )
			break;

		for( int i = 0; i < num_entries; i++ ) {
			if( entries[i].pid == pid )
				entries[i].pid = -1;
		}
	}
}

static void execute_child(const char *cmdline)
{
	char **argv = split(cmdline, " ");

	if( argv == NULL || argv[0] == NULL )
		errx(EXIT_FAILURE, "no args for '%s'", cmdline);

	if( execve(argv[0], argv, (char *[]){}) )
		err(EXIT_FAILURE, "unable to execv for '%s'", cmdline);
}

static void run_nowait(struct entry *ent)
{
	pid_t child_pid;

	if( (ent->pid = child_pid = fork()) ) {
		return;
	}

	execute_child(ent->process);
}

static void run_wait(struct entry *ent)
{
	pid_t child_pid;
	int wstatus;

	if( (ent->pid = child_pid = fork()) ) {
		waitpid(child_pid, &wstatus, 0);
		ent->pid = 0;
		return;
	}

	execute_child(ent->process);
}

/* public function definitions */

int main(int argc, char *argv[])
{
	sigset_t set;
	int status;
	const pid_t my_pid = getpid();

	if( my_pid != 1 )
		warnx("must be PID 1");

	printf("DEBUG: checking options\n");

	parse_command_line(argc, argv);

	printf(	"DEBUG: opt_auto=%d,opt_emerg=%d,opt_def_runlevel=%c,"
			"opt_cfg_filename=%s\n",
			opt_auto, opt_emerg,
			opt_def_runlevel, opt_cfg_filename);

	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, 0);

	read_config();

	run_level = opt_def_runlevel;

	if( run_level == -1 ) {
		warnx("no runlevel specified on command line or inittab");
		run_level = 's';
	}

	printf("DEBUG: run_level set to %c\n", run_level);

	if( sigaction(SIGCHLD, &(const struct sigaction) {
				.sa_handler = chld_handler,
				.sa_flags = SA_NOCLDSTOP
				}, NULL) )
		err(EXIT_FAILURE, "failure on sigaction(SIGCHLD)");

	exit(EXIT_SUCCESS);

	printf("DEBUG: about to fork\n");

	if( fork() ) 
		while(true) wait(&status);

	sigprocmask(SIG_UNBLOCK, &set, 0);

	setsid();
	setpgid(0, 0);

	status = execve("/etc/rc", (char *[]){ "rc", 0 },(char *[]){ 0 });
	warnx("unable to spawn rc");
	return status;
}
