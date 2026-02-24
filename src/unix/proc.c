#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if !defined __linux__
#include <libproc.h>
#endif

#include "../proc.h"

#if defined __APPLE__
#include "../darwin/lldb.h"
#include "../darwin/sip_detect.h"
#endif

static int g_use_shm = 1;

void
procPath(char *fullpath)
{
#if defined __linux__
	char	exepath[64];
	ssize_t ret;
	snprintf(exepath, sizeof(exepath), "/proc/%d/exe", getpid());
	ret = readlink(exepath, fullpath, PATH_MAX);
	assert(ret != -1);
	fullpath[ret] = 0;
#else
	proc_pidpath(getpid(), fullpath, PATH_MAX);
#endif
}

void
procDumpArgs(unsigned nargs, char *const args[])
{
	unsigned i;
	for (i = 0; i < nargs; i++)
		fprintf(stderr, "argv[%d]=%s\n", i, args[i]);
}

static enum procerr
waitchild(int child, int *rc)
{
	enum procerr ret;
	if (-1 != waitpid(child, rc, 0)) {
		int st = *rc;
		if (WIFEXITED(st)) {
			ret = ERR_PROC_OK;
			*rc = WEXITSTATUS(st);
		} else if (WIFSIGNALED(st)) {
			ret = ERR_PROC_SIGNALED;
			*rc = WTERMSIG(st);
		} else if (WIFSTOPPED(st)) {
			ret = ERR_PROC_STOPPED;
			*rc = WSTOPSIG(st);
		} else {
			ret = ERR_PROC_UNKNOWN;
		}
	} else
		ret = ERR_PROC_WAIT;
	return ret;
}

static enum procerr
run_preload(unsigned nargs, char *const args[], int *rc)
{
	int  ret;
	int  child;
	char so[PATH_MAX + 3];
	char fullpath[PATH_MAX];
	procPath(fullpath);
	snprintf(so, sizeof(so), "%s.so", fullpath);
#if defined __linux__
	setenv("LD_PRELOAD", so, 1);
#else
	setenv("DYLD_INSERT_LIBRARIES", so, 1);
	setenv("DYLD_FORCE_FLAT_NAMESPACE", "1", 1);
#endif

	child = fork();
	switch (child) {
	case -1:
		ret = ERR_PROC_FORK;
		break;
	case 0:
		execvp(args[0], args);
		_exit(EXIT_FAILURE);
		break;
	default:
		ret = waitchild(child, rc);
	}
	return ret;
}

#if defined __APPLE__
static int
resolve_exe(const char *cmd, char *out, size_t outsz)
{
	const char *path;
	char	 tmp[PATH_MAX];
	if (!cmd || !*cmd)
		return 0;
	if (strchr(cmd, '/')) {
		if (realpath(cmd, out))
			return 1;
		return 0;
	}
	path = getenv("PATH");
	if (!path)
		return 0;
	while (*path) {
		const char *sep = strchr(path, ':');
		size_t	    n = sep ? (size_t)(sep - path) : strlen(path);
		if (n && n + 1 + strlen(cmd) + 1 < sizeof(tmp)) {
			memcpy(tmp, path, n);
			tmp[n] = 0;
			strcat(tmp, "/");
			strcat(tmp, cmd);
			if (!access(tmp, X_OK) && realpath(tmp, out)) {
				out[outsz - 1] = 0;
				return 1;
			}
		}
		if (!sep)
			break;
		path = sep + 1;
	}
	return 0;
}

static int
use_lldb_backend(unsigned nargs, char *const args[])
{
	const char *backend = getenv("FSAT_BACKEND");
	char	    exe[PATH_MAX];
	if (backend && !strcmp(backend, "preload"))
		return 0;
	if (backend && !strcmp(backend, "lldb"))
		return 1;
	if (backend && !strcmp(backend, "auto")) {
		if (resolve_exe(nargs ? args[0] : "", exe, sizeof(exe)))
			return sip_is_protected(exe);
		return 0;
	}
	return 1;
}
#endif

enum procerr
procRun(unsigned nargs, char *const args[], int *rc)
{
#if defined __APPLE__
	const char *backend = getenv("FSAT_BACKEND");
	if (use_lldb_backend(nargs, args)) {
		if (lldb_available()) {
			g_use_shm = 0;
			return lldb_run(nargs, args, rc);
		}
		if (backend && !strcmp(backend, "lldb"))
			return ERR_PROC_EXEC;
	}
	g_use_shm = 1;
	return run_preload(nargs, args, rc);
#else
	g_use_shm = 1;
	return run_preload(nargs, args, rc);
#endif
}

int
procUsesShm(void)
{
#if defined __APPLE__
	const char *backend = getenv("FSAT_BACKEND");
	if (!backend)
		return !lldb_available();
	if (!strcmp(backend, "lldb"))
		return 0;
	if (!strcmp(backend, "auto"))
		return 1;
	if (!strcmp(backend, "preload"))
		return 1;
#endif
	return g_use_shm;
}
