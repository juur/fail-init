#define _XOPEN_SOURCE 700

#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <err.h>

int main(void)
{
	sigset_t set;
	int status;

	if( getpid() != 1 )
		errx(EXIT_FAILURE, "init: not process 1");

	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, 0);

	if (fork()) while(1) wait(&status);

	sigprocmask(SIG_UNBLOCK, &set, 0);

	setsid();
	setpgid(0, 0);

	return execve("/etc/rc", (char *[]){ "rc", 0 },(char *[]){ 0 });
}
