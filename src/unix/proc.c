#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if !defined __linux__
#include <libproc.h>
#endif

#include "../fsatrace.h"
#include "../proc.h"

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
static bool
trace_enabled(const char *opts, char c)
{
	return !opts || strchr(opts, c);
}

static void
sanitize_path(char *path)
{
	char *nul = strstr(path, "\\0");
	if (nul)
		*nul = 0;
}

static bool
parse_quoted(const char *s, char *out, size_t outsz, const char **next)
{
	size_t i = 0;
	const char *q = strchr(s, '"');
	if (!q)
		return false;
	q++;
	while (*q && *q != '"' && i + 1 < outsz) {
		if (*q == '\\' && q[1]) {
			q++;
			out[i++] = *q++;
			continue;
		}
		out[i++] = *q++;
	}
	if (*q != '"')
		return false;
	out[i] = 0;
	sanitize_path(out);
	if (next)
		*next = q + 1;
	return true;
}

static bool
call_name(const char *line, char *name, size_t namesz)
{
	const char *lparen = strchr(line, '(');
	const char *end;
	const char *start;
	size_t      len;
	if (!lparen)
		return false;
	end = lparen;
	while (end > line && isspace((unsigned char)end[-1]))
		end--;
	start = end;
	while (start > line &&
	    (isalnum((unsigned char)start[-1]) || start[-1] == '_'))
		start--;
	if (start == end)
		return false;
	len = (size_t)(end - start);
	if (len >= namesz)
		len = namesz - 1;
	memcpy(name, start, len);
	name[len] = 0;
	return true;
}

static long
parse_open_flags(const char *line, bool at_variant)
{
	const char *p = strchr(line, '(');
	int	 commas = 0;
	int	 target = at_variant ? 2 : 1;
	bool	 in_quote = false;
	if (!p)
		return 0;
	for (; *p; p++) {
		if (*p == '"')
			in_quote = !in_quote;
		if (!in_quote && *p == ',') {
			commas++;
			if (commas == target)
				return strtol(p + 1, NULL, 0);
		}
		if (!in_quote && *p == ')')
			break;
	}
	return 0;
}

static void
emit_simple(FILE *out, char op, const char *path)
{
	if (path && *path)
		fprintf(out, "%c|%s\n", op, path);
}

static void
emit_move(FILE *out, const char *dst, const char *src)
{
	if (dst && *dst && src && *src)
		fprintf(out, "m|%s|%s\n", dst, src);
}

static void
consume_dtruss_line(FILE *out, const char *opts, const char *line)
{
	char	call[64];
	char	p1[PATH_MAX];
	char	p2[PATH_MAX];
	const char *rest = NULL;
	if (!call_name(line, call, sizeof(call)))
		return;
	if (!strcmp(call, "open") || !strcmp(call, "open_nocancel") ||
	    !strcmp(call, "openat") || !strcmp(call, "openat_nocancel")) {
		const int wmask = O_RDWR | O_WRONLY | O_APPEND | O_CREAT | O_TRUNC;
		long      flags;
		if (!parse_quoted(line, p1, sizeof(p1), NULL))
			return;
		flags = parse_open_flags(line, !strcmp(call, "openat") ||
		    !strcmp(call, "openat_nocancel"));
		if (flags & wmask) {
			if (trace_enabled(opts, 'w'))
				emit_simple(out, 'w', p1);
		} else if (trace_enabled(opts, 'r'))
			emit_simple(out, 'r', p1);
		return;
	}
	if (!strcmp(call, "rename") || !strcmp(call, "renameat") ||
	    !strcmp(call, "renameatx_np")) {
		if (!trace_enabled(opts, 'm'))
			return;
		if (!parse_quoted(line, p1, sizeof(p1), &rest))
			return;
		if (!parse_quoted(rest, p2, sizeof(p2), NULL))
			return;
		emit_move(out, p2, p1);
		return;
	}
	if (!strcmp(call, "unlink") || !strcmp(call, "unlinkat") ||
	    !strcmp(call, "rmdir")) {
		if (trace_enabled(opts, 'd') && parse_quoted(line, p1, sizeof(p1), NULL))
			emit_simple(out, 'd', p1);
		return;
	}
	if (!strcmp(call, "stat") || !strcmp(call, "stat64") ||
	    !strcmp(call, "lstat") || !strcmp(call, "lstat64") ||
	    !strcmp(call, "access") || !strcmp(call, "faccessat") ||
	    !strcmp(call, "getattrlist") || !strcmp(call, "statfs") ||
	    !strcmp(call, "statfs64")) {
		if (trace_enabled(opts, 'q') && parse_quoted(line, p1, sizeof(p1), NULL))
			emit_simple(out, 'q', p1);
	}
}

static int
extract_trace(const char *tracepath, const char *outpath, const char *opts)
{
	FILE *in = fopen(tracepath, "r");
	FILE *out;
	char  line[4096];
	if (!in)
		return -1;
	out = fopen(outpath, "w");
	if (!out) {
		fclose(in);
		return -1;
	}
	while (fgets(line, sizeof(line), in))
		consume_dtruss_line(out, opts, line);
	fclose(out);
	fclose(in);
	return 0;
}

static enum procerr
run_dtruss(unsigned nargs, char *const args[], int *rc)
{
	const char *outpath = getenv(ENVOUT);
	const char *opts = getenv(ENVOPTS);
	const char *trace_calls[] = {
		"open", "open_nocancel", "openat", "openat_nocancel",
		"rename", "renameat", "renameatx_np", "unlink", "unlinkat",
		"rmdir", "stat", "stat64", "lstat", "lstat64", "access",
		"faccessat", "getattrlist", "statfs", "statfs64",
	};
	const size_t ntrace = sizeof(trace_calls) / sizeof(trace_calls[0]);
	char	   tmpl[] = "/tmp/fsatrace.dtruss.XXXXXX";
	char **    dargs;
	size_t     base = 4 + 2 * ntrace;
	size_t     total = base + nargs + 1;
	size_t     i, j;
	int	   fd;
	int	   child;
	enum procerr ret;

	if (!outpath || !*outpath)
		return ERR_PROC_EXEC;
	fd = mkstemp(tmpl);
	if (fd < 0)
		return ERR_PROC_EXEC;
	close(fd);
	dargs = calloc(total, sizeof(char *));
	if (!dargs) {
		unlink(tmpl);
		return ERR_PROC_EXEC;
	}
	i = 0;
	dargs[i++] = "dtruss";
	dargs[i++] = "-f";
	dargs[i++] = "-o";
	dargs[i++] = tmpl;
	for (j = 0; j < ntrace; j++) {
		dargs[i++] = "-t";
		dargs[i++] = (char *)trace_calls[j];
	}
	for (j = 0; j < nargs; j++)
		dargs[i++] = args[j];
	dargs[i] = NULL;

	child = fork();
	if (child == -1) {
		ret = ERR_PROC_FORK;
	} else if (child == 0) {
		execvp("dtruss", dargs);
		_exit(EXIT_FAILURE);
	} else {
		ret = waitchild(child, rc);
		if (extract_trace(tmpl, outpath, opts))
			ret = ERR_PROC_EXEC;
	}
	free(dargs);
	unlink(tmpl);
	return ret;
}
#endif

enum procerr
procRun(unsigned nargs, char *const args[], int *rc)
{
#if defined __APPLE__
	const char *backend = getenv("FSAT_BACKEND");
	if (backend && !strcmp(backend, "preload"))
		return run_preload(nargs, args, rc);
	if (access("/usr/bin/dtruss", X_OK) != 0)
		return run_preload(nargs, args, rc);
	return run_dtruss(nargs, args, rc);
#else
	return run_preload(nargs, args, rc);
#endif
}

int
procUsesShm(void)
{
#if defined __APPLE__
	const char *backend = getenv("FSAT_BACKEND");
	if (backend && !strcmp(backend, "preload"))
		return 1;
	if (access("/usr/bin/dtruss", X_OK) != 0)
		return 1;
	return 0;
#else
	return 1;
#endif
}
