"""Sign in to the dashboard with a Windows account.

The password is checked by Windows itself (LogonUserW) - Prahari never stores it. Members of
the PC's Administrators group (or a domain group nested in it) get the admin role; other Windows
users are refused unless Settings allows them a lower role.

Admin detection copes with UAC: an administrator's interactive logon token is "split"
(TokenElevationTypeLimited), so the Administrators SID is present but deny-only. A split token
therefore counts as an administrator; otherwise CheckTokenMembership decides.

Only available on Windows. Elsewhere `available()` is False and sign-in falls back to
Prahari's own accounts.
"""

from __future__ import annotations

import platform

IS_WINDOWS = platform.system() == "Windows"

LOGON32_LOGON_INTERACTIVE = 2
LOGON32_LOGON_NETWORK = 3
LOGON32_PROVIDER_DEFAULT = 0
TOKEN_ELEVATION_TYPE = 18          # TOKEN_INFORMATION_CLASS.TokenElevationType
ELEVATION_FULL, ELEVATION_LIMITED = 2, 3
SECURITY_IMPERSONATION = 2


def available():
    return IS_WINDOWS


def split_user(username):
    """'DOMAIN\\user' or 'user@domain' or 'user' -> (user, domain). '.' means this PC."""
    name = (username or "").strip()
    if "\\" in name:
        domain, user = name.split("\\", 1)
        return user, domain or "."
    if "@" in name:
        return name, None          # UPN: Windows wants the domain argument empty
    return name, "."


def _win_check(user, domain, password):
    """Returns (ok, is_admin, message). Windows only."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    LogonUserW = advapi32.LogonUserW
    LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                           wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    LogonUserW.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    ok = False
    for logon_type in (LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK):
        if LogonUserW(user, domain, password, logon_type, LOGON32_PROVIDER_DEFAULT, ctypes.byref(token)):
            ok = True
            break
    if not ok:
        err = ctypes.get_last_error()
        messages = {1326: "Wrong user name or password.",
                    1327: "This Windows account has a sign-in restriction.",
                    1330: "This Windows password has expired - change it on the PC first.",
                    1331: "This Windows account is disabled.",
                    1909: "This Windows account is locked out.",
                    1385: "This Windows account may not sign in here."}
        return False, False, messages.get(err, "Wrong user name or password.")

    try:
        # 1. UAC split token => the user is an administrator
        elev = wintypes.DWORD()
        size = wintypes.DWORD()
        GetTokenInformation = advapi32.GetTokenInformation
        GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        if GetTokenInformation(token, TOKEN_ELEVATION_TYPE, ctypes.byref(elev),
                               ctypes.sizeof(elev), ctypes.byref(size)):
            if elev.value in (ELEVATION_FULL, ELEVATION_LIMITED):
                return True, True, ""

        # 2. otherwise ask Windows whether the token is in BUILTIN\Administrators (S-1-5-32-544)
        sid = ctypes.c_void_p()
        ConvertStringSidToSidW = advapi32.ConvertStringSidToSidW
        ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        if not ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid)):
            return True, False, ""
        imp = wintypes.HANDLE()
        DuplicateToken = advapi32.DuplicateToken
        DuplicateToken.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
        is_member = wintypes.BOOL()
        try:
            if DuplicateToken(token, SECURITY_IMPERSONATION, ctypes.byref(imp)):
                CheckTokenMembership = advapi32.CheckTokenMembership
                CheckTokenMembership.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]
                CheckTokenMembership(imp, sid, ctypes.byref(is_member))
                kernel32.CloseHandle(imp)
        finally:
            kernel32.LocalFree(sid)
        return True, bool(is_member.value), ""
    finally:
        kernel32.CloseHandle(token)


def check(username, password, checker=None):
    """(ok, is_admin, display_name, message). `checker` lets tests replace the Windows call."""
    user, domain = split_user(username)
    if not user or not password:
        return False, False, "", "Enter your Windows user name and password."
    if checker is None:
        if not IS_WINDOWS:
            return False, False, "", "Windows sign-in is only available on Windows."
        checker = _win_check
    try:
        ok, is_admin, msg = checker(user, domain, password)
    except Exception as exc:  # never let a ctypes problem break the login page
        return False, False, "", f"Windows sign-in failed ({exc.__class__.__name__})."
    display = user if domain in (None, ".") else f"{domain}\\{user}"
    return ok, is_admin, display, msg


def role_for(is_admin, cfg):
    """Admins -> 'admin'. Others -> settings auth.windows_users_role ('none' = refused)."""
    if is_admin:
        return "admin"
    other = ((cfg or {}).get("auth") or {}).get("windows_users_role") or "none"
    return other if other in ("viewer", "engineer") else None
