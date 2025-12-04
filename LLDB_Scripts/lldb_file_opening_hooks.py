import lldb
MAX_PATH_LENGTH = 1024

def get_string_arg(frame, arg_idx, process):
    target = process.GetTarget()
    arch = target.GetTriple().split('-')[0]
    if "arm" in arch:
        regs = ["x0", "x1"]
    else:
        regs = ["rdi", "rsi"]
    addr = frame.FindRegister(regs[arg_idx]).GetValueAsUnsigned()
    string = process.ReadCStringFromMemory(addr, MAX_PATH_LENGTH, lldb.SBError())
    return string

def bp_open_hook(frame, bp_loc, dict):
    path = get_string_arg(frame, 0, frame.GetThread().GetProcess())
    print(f"\n[LLDB HOOK] open() called. Path: '{path}'")
    return False

def bp_openat_hook(frame, bp_loc, dict):
    path = get_string_arg(frame, 1, frame.GetThread().GetProcess())
    print(f"\n[LLDB HOOK] openat() called. Path: '{path}'")
    return False

def bp_fopen_hook(frame, bp_loc, dict):
    process = frame.GetThread().GetProcess()
    filename = get_string_arg(frame, 0, process)
    mode = get_string_arg(frame, 1, process)
    print(f"\n[LLDB HOOK] fopen() called. Path: '{filename}', Mode: '{mode}'")
    return False

def __lldb_init_module(debugger, internal_dict):
    print("File monitoring script loaded")