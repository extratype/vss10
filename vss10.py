import sys
import re
import binascii
import contextlib as cl
import time
import locale
import subprocess
import os
import os.path as osp
import ctypes
import ctypes.wintypes as cwt

import win32con
import win32api
import win32process
import win32security as wsec


# noinspection PyPep8Naming
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", cwt.LPVOID),
                ("AllocationBase", cwt.LPVOID),
                ("AllocationProtect", cwt.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", cwt.DWORD),
                ("Protect", cwt.DWORD),
                ("Type", cwt.DWORD)]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", cwt.LPVOID),
                ("SizeOfImage", cwt.DWORD),
                ("EntryPoint", cwt.LPVOID)]


VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    cwt.HANDLE, cwt.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t

GetModuleInformation = ctypes.windll.psapi.GetModuleInformation
GetModuleInformation.argtypes = [
    cwt.HANDLE, cwt.HMODULE, ctypes.POINTER(MODULEINFO), cwt.DWORD]
GetModuleInformation.restype = ctypes.c_bool

WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    cwt.HANDLE, cwt.LPVOID, cwt.LPCVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = ctypes.c_bool


def run_powershell(cmd):
    output = subprocess.check_output(
        ['powershell', '-EncodedCommand',
         binascii.b2a_base64(cmd.encode('utf-16le'), newline=False)])
    return output.rstrip(b'\n')


def run_service(name: str):
    if '\'' in name:
        raise ValueError(f'invalid service: {name}')

    while True:
        cmd = '$x = (Get-CimInstance Win32_Service | Where-Object Name' \
              ' -eq \'{}\');'.format(name) + \
              'Write-Host ($x.State, $x.ProcessId) -Separator `n;'
        state, pid = run_powershell(cmd) \
            .decode(locale.getpreferredencoding()).split('\n')
        pid = int(pid)

        if state == 'Running':
            break
        if state == 'Start Pending':
            time.sleep(1)
            continue
        if state == 'Continue Pending':
            time.sleep(1)
            continue

        subprocess.check_output(['sc', 'start', name])
        time.sleep(1)
        continue

    return pid


def acquire_debug_priv():
    with cl.closing(wsec.OpenProcessToken(
            win32api.GetCurrentProcess(),
            wsec.TOKEN_ADJUST_PRIVILEGES | wsec.TOKEN_QUERY)) as h:
        luid = wsec.LookupPrivilegeValue(None, wsec.SE_DEBUG_NAME)
        wsec.AdjustTokenPrivileges(h, False, [(luid, wsec.SE_PRIVILEGE_ENABLED)])


class Error(Exception):
    pass


enable_logging = True


def log(*values, file=sys.stdout, flush=False):
    """print patching infos and errors"""
    if enable_logging:
        print(*values, file=file, flush=flush)


def patch_vss_module(pid: int, name: str, org: bytes, new: bytes):
    """patch (vsstrace_ptr org) -> (vsstrace_ptr new) in a module"""
    hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION
                                 | win32con.PROCESS_VM_OPERATION
                                 | win32con.PROCESS_VM_READ
                                 | win32con.PROCESS_VM_WRITE,
                                 0, pid)
    with cl.closing(hproc):
        # find name, vsstrace.dll
        mods = win32process.EnumProcessModules(hproc)
        mod_names = [
            osp.basename(win32process.GetModuleFileNameEx(hproc, hmod)).lower()
            for hmod in mods]

        try:
            mod_addr = int(mods[mod_names.index(name.lower())])
        except ValueError:
            raise Error(f'failed to patch process {pid}: module {name} is not loaded')
        try:
            vsstrace_ptr = int(mods[mod_names.index('vsstrace.dll')]).to_bytes(
                8, 'little')
        except ValueError:
            vsstrace_ptr = b'\x00'*8

        # find .data
        modinfo = MODULEINFO()
        if not GetModuleInformation(int(hproc), mod_addr, ctypes.byref(modinfo),
                                    ctypes.sizeof(modinfo)):
            raise ctypes.WinError()

        addr = mod_addr
        while addr < modinfo.lpBaseOfDll + modinfo.SizeOfImage:
            mbi = MEMORY_BASIC_INFORMATION()
            if not VirtualQueryEx(int(hproc), addr, ctypes.byref(mbi),
                                  ctypes.sizeof(mbi)):
                raise ctypes.WinError()
            if mbi.Protect & win32con.PAGE_READWRITE:
                break
            addr += mbi.RegionSize
        else:
            raise Error(f'failed to patch process {pid}: .data region not found')

        # patch .data
        data: bytes = win32process.ReadProcessMemory(hproc, addr, mbi.RegionSize)
        try:
            org_data = vsstrace_ptr + org
            new_data = vsstrace_ptr + new
            off = data.index(org_data)
        except ValueError:
            try:
                org_data = b'\x00'*8 + org
                new_data = b'\x00'*8 + new
                off = data.index(org_data)
            except ValueError:
                if data.find(new) >= 0:
                    log(f'already patched module {name} of process {pid}')
                    return
                else:
                    raise Error(f'failed to patch process {pid}: pattern not found')

        buf = ctypes.create_string_buffer(new_data)
        bufsiz = len(new_data)
        if not WriteProcessMemory(int(hproc), addr + off, buf, bufsiz, None):
            raise ctypes.WinError()
        log(f'patched module {name} of process {pid}')


def get_file_version(path):
    if '\'' in path:
        raise ValueError(f'invalid path: {path}')

    cmd = '$x = \'{}\';'.format(path) + \
          '$x = (Get-Command $x).FileVersionInfo;' \
          'Write-Host (\'{0}.{1}.{2}.{3}\'' \
          '-f ($x.FileMajorPart, $x.FileMinorPart, $x.FileBuildPart, $x.FilePrivatePart));'
    return run_powershell(cmd).decode(locale.getpreferredencoding())


def locate_pattern(pattern: bytes, data: bytes, limit: int):
    """find unique regex *pattern* in *data* of length up to *limit* bytes"""
    result = None
    for m in re.finditer(pattern, data, re.DOTALL):
        start = m.start()
        end = m.end()
        if end - start > limit:
            # too long to match
            continue
        if result is not None:
            raise Error('failed to patch: multiple patterns found')
        result = m

    if result is None:
        raise Error('failed to patch: pattern not found')
    return result


def patch_vssadmin(data: bytes):
    # force CVssSKU::ms_eSKU = 2
    pattern = [b'\x76..{1,30}',     # jbe ...
               b'\xeb..{1,30}',     # jmp ...
               b'\x1b\xc9',         # sbb ecx, ecx
               b'\x83\xe1\x02',     # and ecx, 2
               b'\x83\xc1\x02']     # add ecx, 2
    pattern = b''.join(pattern)
    m = locate_pattern(pattern, data, 60)

    new_data = bytearray(data)
    new_data[m.start()] = 0xeb      # jbe -> jmp
    return bytes(new_data)


def patch_vssapi(data: bytes):
    # force CVssSKU::ms_eSKU = 2
    pattern1 = [b'\x0f\x1f\x44\x00\x00',                        # nop
                b'\x85\xc0',                                    # test eax, eax
                b'\x0f\x84..(\x00|\x01)\x00.{1,30}',            # jz ...
                b'(\x0f[\x80-\x8f]..(\x00|\x01)\x00).{1,30}',   # jbe ...
                b'\x0f[\x80-\x8f]..(\x00|\x01)\x00',            # jnz
                b'\x89....\x00']                                # mov
    pattern1 = b''.join(pattern1)
    m1 = locate_pattern(pattern1, data, 60)

    pattern2 = [b'\x76..{1,30}',    # jbe ...
                b'\xeb..{1,30}',    # jmp ...
                b'\x1b\xc9',        # sbb ecx, ecx
                b'\x83\xe1\x02',    # and ecx, 2
                b'\x83\xc1\x02']    # add ecx, 2
    pattern2 = b''.join(pattern2)
    m2 = locate_pattern(pattern2, data, 60)

    new_data = bytearray(data)

    pos1 = m1.start(2)
    new_data[pos1] = 0xe9                                       # jbe -> jmp
    new_data[pos1+1:pos1+5] = \
        (int.from_bytes(new_data[pos1+2:pos1+6], 'little') + 1) \
        .to_bytes(4, 'little')                                  # adjust pointer
    new_data[pos1+5] = 0x90                                     # nop

    pos2 = m2.start()
    new_data[pos2] = 0xeb           # jbe -> jmp
    return bytes(new_data)


def vss():
    acquire_debug_priv()

    # vssapi.dll, vsstrace.dll are imported
    pid = run_service('VSS')

    # CVssSKU::ms_eSKU = 2
    # CVssSKU::ms_bTransportableShadowsAllowed = 1
    try:
        patch_vss_module(pid, 'vssapi.dll',
                         bytes([1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
                         bytes([1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0]))
    except Error as e:
        log(str(e), file=sys.stderr, flush=True)

    # CVssSKU::ms_eSKU = 2
    # CVssSKU::ms_bTransportableShadowsAllowed = 1
    try:
        patch_vss_module(pid, 'VSSVC.exe',
                         bytes([1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
                         bytes([1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]))
    except Error as e:
        log(str(e), file=sys.stderr, flush=True)


def swprv():
    acquire_debug_priv()

    # vsstrace.dll is imported
    # vssapi.dll is delayed imported
    pid = run_service('swprv')

    # CVssSKU::ms_eSKU = 2
    # CVssSKU::ms_bTransportableShadowsAllowed = 1
    try:
        patch_vss_module(pid, 'vssapi.dll',
                         bytes([1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
                         bytes([1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0]))
    except Error as e:
        log(str(e), file=sys.stderr, flush=True)

    # CVssSKU::ms_eSKU = 2
    try:
        patch_vss_module(pid, 'swprv.dll',
                         bytes([1, 0, 0, 0, 1, 0, 0, 0]),
                         bytes([1, 0, 0, 0, 2, 0, 0, 0]))
    except Error as e:
        log(str(e), file=sys.stderr, flush=True)


def vssadmin(simpler=False):
    if not simpler:
        gfv = get_file_version
    else:
        def gfv(p):
            return os.stat(p).st_mtime_ns

    vssadmin_org = r'C:\Windows\System32\vssadmin.exe'
    vssadmin_new = osp.join(osp.dirname(__file__), 'vssadmin.exe')
    if not osp.exists(vssadmin_new) or gfv(vssadmin_org) != gfv(vssadmin_new):
        open(vssadmin_new, 'wb').write(
            patch_vssadmin(open(vssadmin_org, 'rb').read()))
        log('patched vssadmin.exe')
    else:
        log('already patched vssadmin.exe')

    vssadmin_mui_org = r'C:\Windows\System32\en-US\vssadmin.exe.mui'
    vssadmin_mui_new = osp.join(osp.dirname(__file__), 'en-US', 'vssadmin.exe.mui')
    if not osp.exists(vssadmin_mui_new) or gfv(vssadmin_mui_org) != gfv(vssadmin_mui_new):
        os.makedirs(osp.dirname(vssadmin_mui_new), exist_ok=True)
        open(vssadmin_mui_new, 'wb').write(open(vssadmin_mui_org, 'rb').read())

    vssapi_org = r'C:\Windows\System32\vssapi.dll'
    vssapi_new = osp.join(osp.dirname(__file__), 'vssapi.dll')
    if not osp.exists(vssapi_new) or gfv(vssapi_org) != gfv(vssapi_new):
        open(vssapi_new, 'wb').write(
            patch_vssapi(open(vssapi_org, 'rb').read()))
        log('patched vssapi.dll')
    else:
        log('already patched vssapi.dll')


def run_vssadmin(args):
    # no output, only from vssadmin
    global enable_logging
    enable_logging = False

    vss()
    swprv()
    vssadmin(True)  # faster startup

    vssadmin_new = osp.join(osp.dirname(__file__), 'vssadmin.exe')
    return subprocess.run([vssadmin_new, *args]).returncode


def usage():
    print('vss10.py vss                 Start and patch Volume Shadow Copy service')
    print('vss10.py swprv               Start and patch Microsoft Software Shadow Copy Provider service')
    print('vss10.py vssadmin            Copy and patch vssadmin')
    print('vss10.py vssadmin [arg]...   All of the above, then run vssadmin')
    print('', end='', flush=True)


def main():
    # VER_NT_WORKSTATION
    if sys.getwindowsversion().product_type != 1:
        print('This edition of Windows is not supported.')
        return 1
    if 'AMD64' not in sys.version:
        print('Please run this script on Python AMD64.')
        return 1

    args = sys.argv[1:]
    if not args:
        usage()
        return 1

    name, args = args[0], args[1:]
    if name == 'vssadmin':
        if not args:
            vssadmin()
        else:
            return run_vssadmin(args)
    elif name == 'vss' and not args:
        vss()
    elif name == 'swprv' and not args:
        swprv()
    else:
        print('Invalid argument.')
        usage()
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
