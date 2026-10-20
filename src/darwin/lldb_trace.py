#!/usr/bin/env python3
import argparse
import lldb
import os
import sys

OUT = None
ENABLED = set("rwmdq")

# Callback body templates - LLDB executes these inline
# They write to a global file handle set up before launch

_CB_OPEN = '''
import os
def _u64(v):
    try: return int(v, 0) if v else 0
    except: return 0
triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
regs = ["x0", "x1"] if "arm64" in triple or "aarch64" in triple else ["rdi", "rsi"]
path_addr = _u64(frame.FindRegister(regs[0]).GetValue())
flags = _u64(frame.FindRegister(regs[1]).GetValue())
if path_addr:
    err = lldb.SBError()
    path = frame.GetThread().GetProcess().ReadCStringFromMemory(path_addr, 4096, err)
    if path and err.Success():
        wmask = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
        op = "w" if (flags & wmask) else "r"
        with open(__fsat_out__, "a") as f:
            if op in __fsat_opts__:
                f.write(f"{op}|{path}\\n")
return False
'''

_CB_OPENAT = '''
import os
def _u64(v):
    try: return int(v, 0) if v else 0
    except: return 0
triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
regs = ["x0", "x1", "x2"] if "arm64" in triple or "aarch64" in triple else ["rdi", "rsi", "rdx"]
path_addr = _u64(frame.FindRegister(regs[1]).GetValue())
flags = _u64(frame.FindRegister(regs[2]).GetValue())
if path_addr:
    err = lldb.SBError()
    path = frame.GetThread().GetProcess().ReadCStringFromMemory(path_addr, 4096, err)
    if path and err.Success():
        wmask = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
        op = "w" if (flags & wmask) else "r"
        with open(__fsat_out__, "a") as f:
            if op in __fsat_opts__:
                f.write(f"{op}|{path}\\n")
return False
'''

_CB_RENAME = '''
def _u64(v):
    try: return int(v, 0) if v else 0
    except: return 0
triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
regs = ["x0", "x1"] if "arm64" in triple or "aarch64" in triple else ["rdi", "rsi"]
src_addr = _u64(frame.FindRegister(regs[0]).GetValue())
dst_addr = _u64(frame.FindRegister(regs[1]).GetValue())
if src_addr and dst_addr:
    err = lldb.SBError()
    proc = frame.GetThread().GetProcess()
    src = proc.ReadCStringFromMemory(src_addr, 4096, err)
    dst = proc.ReadCStringFromMemory(dst_addr, 4096, err)
    if src and dst and "m" in __fsat_opts__:
        with open(__fsat_out__, "a") as f:
            f.write(f"m|{dst}|{src}\\n")
return False
'''

_CB_UNLINK = '''
def _u64(v):
    try: return int(v, 0) if v else 0
    except: return 0
triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
reg = "x0" if "arm64" in triple or "aarch64" in triple else "rdi"
path_addr = _u64(frame.FindRegister(reg).GetValue())
if path_addr:
    err = lldb.SBError()
    path = frame.GetThread().GetProcess().ReadCStringFromMemory(path_addr, 4096, err)
    if path and err.Success() and "d" in __fsat_opts__:
        with open(__fsat_out__, "a") as f:
            f.write(f"d|{path}\\n")
return False
'''

_CB_UNLINKAT = '''
def _u64(v):
    try: return int(v, 0) if v else 0
    except: return 0
triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
reg = "x1" if "arm64" in triple or "aarch64" in triple else "rsi"
path_addr = _u64(frame.FindRegister(reg).GetValue())
if path_addr:
    err = lldb.SBError()
    path = frame.GetThread().GetProcess().ReadCStringFromMemory(path_addr, 4096, err)
    if path and err.Success() and "d" in __fsat_opts__:
        with open(__fsat_out__, "a") as f:
            f.write(f"d|{path}\\n")
return False
'''

_CB_STAT = '''
def _u64(v):
    try: return int(v, 0) if v else 0
    except: return 0
triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
reg = "x0" if "arm64" in triple or "aarch64" in triple else "rdi"
path_addr = _u64(frame.FindRegister(reg).GetValue())
if path_addr:
    err = lldb.SBError()
    path = frame.GetThread().GetProcess().ReadCStringFromMemory(path_addr, 4096, err)
    if path and err.Success() and "q" in __fsat_opts__:
        with open(__fsat_out__, "a") as f:
            f.write(f"q|{path}\\n")
return False
'''

_CB_FACCESSAT = '''
def _u64(v):
    try: return int(v, 0) if v else 0
    except: return 0
triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
reg = "x1" if "arm64" in triple or "aarch64" in triple else "rsi"
path_addr = _u64(frame.FindRegister(reg).GetValue())
if path_addr:
    err = lldb.SBError()
    path = frame.GetThread().GetProcess().ReadCStringFromMemory(path_addr, 4096, err)
    if path and err.Success() and "q" in __fsat_opts__:
        with open(__fsat_out__, "a") as f:
            f.write(f"q|{path}\\n")
return False
'''


def _bp(target, name, body):
    bp = target.BreakpointCreateByName(name)
    if bp and bp.IsValid() and bp.GetNumLocations() > 0:
        bp.SetScriptCallbackBody(body)


def run(out_path, opts, cmd):
    global OUT, ENABLED
    ENABLED = set(opts) if opts else set("rwmdq")

    # Create empty output file
    with open(out_path, "w") as f:
        pass

    lldb.SBDebugger.Initialize()
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)

    # Set globals that callbacks can access
    interp = debugger.GetCommandInterpreter()
    lldb.debugger = debugger
    # Inject globals into LLDB's Python environment
    debugger.HandleCommand(f'script __fsat_out__ = "{out_path}"')
    debugger.HandleCommand(f'script __fsat_opts__ = set("{opts}")')

    target = debugger.CreateTarget(cmd[0])
    if not target or not target.IsValid():
        lldb.SBDebugger.Destroy(debugger)
        lldb.SBDebugger.Terminate()
        return 127

    _bp(target, "open", _CB_OPEN)
    _bp(target, "open$NOCANCEL", _CB_OPEN)
    _bp(target, "openat", _CB_OPENAT)
    _bp(target, "openat$NOCANCEL", _CB_OPENAT)
    _bp(target, "rename", _CB_RENAME)
    _bp(target, "renameat", _CB_RENAME)
    _bp(target, "renameatx_np", _CB_RENAME)
    _bp(target, "unlink", _CB_UNLINK)
    _bp(target, "unlinkat", _CB_UNLINKAT)
    _bp(target, "rmdir", _CB_UNLINK)
    _bp(target, "stat", _CB_STAT)
    _bp(target, "stat64", _CB_STAT)
    _bp(target, "lstat", _CB_STAT)
    _bp(target, "lstat64", _CB_STAT)
    _bp(target, "access", _CB_STAT)
    _bp(target, "getattrlist", _CB_STAT)
    _bp(target, "statfs", _CB_STAT)
    _bp(target, "statfs64", _CB_STAT)
    _bp(target, "faccessat", _CB_FACCESSAT)

    process = target.LaunchSimple(cmd[1:], None, os.getcwd())
    if not process or not process.IsValid():
        lldb.SBDebugger.Destroy(debugger)
        lldb.SBDebugger.Terminate()
        return 127

    while process.GetState() == lldb.eStateStopped:
        process.Continue()

    code = process.GetExitStatus()
    lldb.SBDebugger.Destroy(debugger)
    lldb.SBDebugger.Terminate()
    return code


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--opts", default="")
    parser.add_argument("cmd", nargs=argparse.REMAINDER)
    ns = parser.parse_args()

    cmd = ns.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        return 2
    return run(ns.out, ns.opts, cmd)


if __name__ == "__main__":
    sys.exit(main())
