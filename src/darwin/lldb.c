#include "lldb.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static enum procerr
waitchild(int child, int *rc)
{
	if (-1 == waitpid(child, rc, 0))
		return ERR_PROC_WAIT;
	if (WIFEXITED(*rc)) {
		*rc = WEXITSTATUS(*rc);
		return ERR_PROC_OK;
	}
	if (WIFSIGNALED(*rc)) {
		*rc = WTERMSIG(*rc);
		return ERR_PROC_SIGNALED;
	}
	if (WIFSTOPPED(*rc)) {
		*rc = WSTOPSIG(*rc);
		return ERR_PROC_STOPPED;
	}
	return ERR_PROC_UNKNOWN;
}

int
lldb_available(void)
{
	int child;
	int st = 0;
	char *const args[] = {
		"/usr/bin/python3",
		"-c",
		"import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('lldb') else 1)",
		NULL,
	};
	if (access("/usr/bin/python3", X_OK) != 0)
		return 0;
	child = fork();
	if (child < 0)
		return 0;
	if (child == 0) {
		execv("/usr/bin/python3", args);
		_exit(EXIT_FAILURE);
	}
	if (waitpid(child, &st, 0) < 0)
		return 0;
	return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

enum procerr
lldb_run(unsigned nargs, char *const args[], int *rc)
{
	char	   script[PATH_MAX];
	char	   outopt[PATH_MAX + 32];
	char	   optsopt[128];
	const char *out = getenv("FSAT_OUT");
	const char *opts = getenv("FSAT_OPTS");
	char **    largs;
	size_t	   i;
	size_t	   total = 5 + nargs + 1;
	int	   child;

	if (!lldb_available() || !out || !*out)
		return ERR_PROC_EXEC;
	if (!opts)
		opts = "";

	snprintf(script, sizeof(script), "%s/src/darwin/lldb_trace.py",
	    getenv("PWD") ? getenv("PWD") : ".");
	snprintf(outopt, sizeof(outopt), "--out=%s", out);
	snprintf(optsopt, sizeof(optsopt), "--opts=%s", opts);

	largs = calloc(total, sizeof(char *));
	if (!largs)
		return ERR_PROC_EXEC;

	i = 0;
	largs[i++] = "/usr/bin/python3";
	largs[i++] = script;
	largs[i++] = outopt;
	largs[i++] = optsopt;
	largs[i++] = "--";
	for (size_t j = 0; j < nargs; j++)
		largs[i++] = args[j];
	largs[i] = NULL;

	child = fork();
	if (child == -1) {
		free(largs);
		return ERR_PROC_FORK;
	}
	if (child == 0) {
		execv("/usr/bin/python3", largs);
		_exit(EXIT_FAILURE);
	}
	free(largs);
	return waitchild(child, rc);
}
