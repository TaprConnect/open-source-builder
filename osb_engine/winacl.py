"""Windows DACL inspection for the private store (S02-006).

Allow ACEs may name only the current user, SYSTEM, Administrators or OWNER RIGHTS.
Inherit-only and deny ACEs are ignored; any other ACE type is reported as unknown.
"""
import ctypes
import os
from ctypes import wintypes

_ALLOWED_WELL_KNOWN = {"S-1-5-18", "S-1-5-32-544", "S-1-3-4"}  # SYSTEM, Administrators, OWNER RIGHTS
_ACCESS_ALLOWED, _ACCESS_DENIED = 0, 1
_A = ctypes.WinDLL("advapi32", use_last_error=True)
_K = ctypes.WinDLL("kernel32", use_last_error=True)
_K.GetCurrentProcess.restype = wintypes.HANDLE
_K.CloseHandle.argtypes = [wintypes.HANDLE]
_K.LocalFree.argtypes = [ctypes.c_void_p]
_A.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_A.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
_A.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
_A.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
_A.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                     ctypes.POINTER(ctypes.c_void_p)]
_A.GetNamedSecurityInfoW.restype = wintypes.DWORD


def _current_user_sid():
    advapi32, kernel32 = _A, _K
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken")
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation")
        return _sid_string(ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0])
    finally:
        kernel32.CloseHandle(token)


def _sid_string(psid):
    advapi32, kernel32 = _A, _K
    out = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(out)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW")
    try:
        return out.value
    finally:
        kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))


def unexpected_principals(path):
    """Return SIDs granted allow access other than owner-user/SYSTEM/Administrators; ['NULL-DACL'] if unprotected."""
    advapi32, kernel32 = _A, _K
    dacl, sd = ctypes.c_void_p(), ctypes.c_void_p()
    rc = advapi32.GetNamedSecurityInfoW(os.fspath(path), 1, 0x4, None, None, ctypes.byref(dacl), None, ctypes.byref(sd))
    if rc:
        raise OSError(rc, "GetNamedSecurityInfoW")
    try:
        if not dacl.value:
            return ["NULL-DACL"]
        allowed = _ALLOWED_WELL_KNOWN | {_current_user_sid()}
        count = ctypes.cast(dacl, ctypes.POINTER(ctypes.c_ushort))[2]  # ACL.AceCount
        found = []
        for index in range(count):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error(), "GetAce")
            ace_type = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))[0]
            if ace_type == _ACCESS_DENIED:
                continue
            if ace_type != _ACCESS_ALLOWED:
                found.append(f"UNSUPPORTED-ACE-{ace_type}")
                continue
            sid = _sid_string(ace.value + 8)  # ACE_HEADER(4) + ACCESS_MASK(4)
            if sid not in allowed:
                found.append(sid)
        return found
    finally:
        kernel32.LocalFree(sd)
