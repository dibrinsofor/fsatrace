#!/usr/bin/env python3
import argparse
import lldb
import os
import sys

OUT = None
ENABLED = set("rwmdq")


def _u64(v):
    if not v:
        return 0
    try:
        return int(v, 0)
    except Exception:
        return 0


def _arch_regs(frame):
    triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
    if "arm64" in triple or "aarch64" in triple:
        return ["x0", "x1", "x2", "x3"]
    return ["rdi", "rsi", "rdx", "rcx"]


def _arg_ptr(frame, idx):
    regs = _arch_regs(frame)
    if idx >= len(regs):
        return 0
    return _u64(frame.FindRegister(regs[idx]).GetValue())


def _arg_int(frame, idx):
    return _arg_ptr(frame, idx)


def _read_cstr(frame, addr):
    if not addr:
        return None
    err = lldb.SBError()
    s = frame.GetThread().GetProcess().ReadCStringFromMemory(addr, 4096, err)
    if not err.Success() or s is None:
        return None
    return s


def _emit(line):
    if OUT is not None:
        OUT.write(line + "\n")
        OUT.flush()


def _cb_open(frame, bp_loc, _dict):
    path = _read_cstr(frame, _arg_ptr(frame, 0))
    flags = _arg_int(frame, 1)
    if not path:
        return False
    wmask = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
    op = "w" if (flags & wmask) else "r"
    if op in ENABLED:
        _emit(f"{op}|{path}")
    return False


def _cb_openat(frame, bp_loc, _dict):
    path = _read_cstr(frame, _arg_ptr(frame, 1))
    flags = _arg_int(frame, 2)
    if not path:
        return False
    wmask = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
    op = "w" if (flags & wmask) else "r"
    if op in ENABLED:
        _emit(f"{op}|{path}")
    return False


def _cb_rename(frame, bp_loc, _dict):
    src = _read_cstr(frame, _arg_ptr(frame, 0))
    dst = _read_cstr(frame, _arg_ptr(frame, 1))
    if src and dst and "m" in ENABLED:
        _emit(f"m|{dst}|{src}")
    return False


def _cb_unlink(frame, bp_loc, _dict):
    path = _read_cstr(frame, _arg_ptr(frame, 0))
    if path and "d" in ENABLED:
        _emit(f"d|{path}")
    return False


def _cb_unlinkat(frame, bp_loc, _dict):
    path = _read_cstr(frame, _arg_ptr(frame, 1))
    if path and "d" in ENABLED:
        _emit(f"d|{path}")
    return False


def _cb_statlike(frame, bp_loc, _dict):
    path = _read_cstr(frame, _arg_ptr(frame, 0))
    if path and "q" in ENABLED:
        _emit(f"q|{path}")
    return False


def _cb_faccessat(frame, bp_loc, _dict):
    path = _read_cstr(frame, _arg_ptr(frame, 1))
    if path and "q" in ENABLED:
        _emit(f"q|{path}")
    return False


def _bp(target, name, cb):
    bp = target.BreakpointCreateByName(name)
    if bp and bp.IsValid() and bp.GetNumLocations() > 0:
        bp.SetScriptCallbackFunction(cb)


def run(out_path, opts, cmd):
    global OUT, ENABLED
    ENABLED = set(opts) if opts else set("rwmdq")
    OUT = open(out_path, "w", encoding="utf-8")

    lldb.SBDebugger.Initialize()
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)

    target = debugger.CreateTarget(cmd[0])
    if not target or not target.IsValid():
        OUT.close()
        return 127

    mod = __name__
    _bp(target, "open", f"{mod}._cb_open")
    _bp(target, "open_nocancel", f"{mod}._cb_open")
    _bp(target, "openat", f"{mod}._cb_openat")
    _bp(target, "openat_nocancel", f"{mod}._cb_openat")
    _bp(target, "rename", f"{mod}._cb_rename")
    _bp(target, "renameat", f"{mod}._cb_rename")
    _bp(target, "renameatx_np", f"{mod}._cb_rename")
    _bp(target, "unlink", f"{mod}._cb_unlink")
    _bp(target, "unlinkat", f"{mod}._cb_unlinkat")
    _bp(target, "rmdir", f"{mod}._cb_unlink")
    _bp(target, "stat", f"{mod}._cb_statlike")
    _bp(target, "stat64", f"{mod}._cb_statlike")
    _bp(target, "lstat", f"{mod}._cb_statlike")
    _bp(target, "lstat64", f"{mod}._cb_statlike")
    _bp(target, "access", f"{mod}._cb_statlike")
    _bp(target, "getattrlist", f"{mod}._cb_statlike")
    _bp(target, "statfs", f"{mod}._cb_statlike")
    _bp(target, "statfs64", f"{mod}._cb_statlike")
    _bp(target, "faccessat", f"{mod}._cb_faccessat")

    process = target.LaunchSimple(cmd[1:], None, os.getcwd())
    if not process or not process.IsValid():
        lldb.SBDebugger.Destroy(debugger)
        lldb.SBDebugger.Terminate()
        OUT.close()
        return 127

    while process.GetState() == lldb.eStateStopped:
        process.Continue()

    code = process.GetExitStatus()
    lldb.SBDebugger.Destroy(debugger)
    lldb.SBDebugger.Terminate()
    OUT.close()
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
