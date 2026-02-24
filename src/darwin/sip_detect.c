#include "sip_detect.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool
path_heuristic(const char *path)
{
	static const char *prefixes[] = {
		"/System/",
		"/bin/",
		"/sbin/",
		"/usr/bin/",
		"/usr/sbin/",
	};
	size_t i;
	for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		size_t n = strlen(prefixes[i]);
		if (!strncmp(path, prefixes[i], n))
			return true;
	}
	return false;
}

static bool
has_restrict_segment(const char *path)
{
	char cmd[PATH_MAX + 64];
	FILE *fp;
	char line[1024];
	snprintf(cmd, sizeof(cmd), "/usr/bin/otool -l '%s' 2>/dev/null", path);
	fp = popen(cmd, "r");
	if (!fp)
		return false;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "__RESTRICT")) {
			pclose(fp);
			return true;
		}
	}
	pclose(fp);
	return false;
}

static bool
has_rootless_entitlements(const char *path)
{
	char cmd[PATH_MAX + 128];
	FILE *fp;
	char line[1024];
	snprintf(cmd, sizeof(cmd),
	    "/usr/bin/codesign -d --entitlements :- '%s' 2>&1", path);
	fp = popen(cmd, "r");
	if (!fp)
		return false;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "com.apple.rootless") ||
		    strstr(line, "com.apple.private.security")) {
			pclose(fp);
			return true;
		}
	}
	pclose(fp);
	return false;
}

int
sip_is_protected(const char *exe)
{
	char resolved[PATH_MAX];
	struct stat st;
	if (!exe || !*exe)
		return 0;
	if (!realpath(exe, resolved))
		return 0;
	if (stat(resolved, &st))
		return 0;
	if (!S_ISREG(st.st_mode))
		return 0;
	return path_heuristic(resolved) || has_rootless_entitlements(resolved) ||
	    has_restrict_segment(resolved);
}
