#ifndef FSATRACE_DARWIN_LLDB_H
#define FSATRACE_DARWIN_LLDB_H

#include "../proc.h"

enum procerr lldb_run(unsigned nargs, char *const args[], int *rc);
int	     lldb_available(void);

#endif
