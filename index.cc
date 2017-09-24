#include <node.h>
#include <v8.h>
#include "Windows.h"
#include "Shlobj.h"
#include <string>
#include <sstream>
#include <iomanip>
#include "utils.h"
#include <tchar.h>

using namespace v8;


/*++
Routine Description: This routine returns TRUE if the caller's
process is a member of the Administrators local group. Caller is NOT
expected to be impersonating anyone and is expected to be able to
open its own process and process token.
Arguments: None.
Return Value:
   TRUE - Caller has Administrators local group.
   FALSE - Caller does not have Administrators local group. --
*/
BOOL _isUserAdmin(VOID) {
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    b = AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup);

    if (b) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) {
             b = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }

    return b;
}


// Definition of the function this sample is all about.
// The szApp, szCmdLine, szCurrDir, si, and pi parameters are passed directly to CreateProcessWithTokenW.
// sErrorInfo returns text describing any error that occurs.
// Returns "true" on success, "false" on any error.
// It is up to the caller to close the HANDLEs returned in the PROCESS_INFORMATION structure.
bool RunAsDesktopUser(
    __in    const wchar_t *       szApp,
    __in    wchar_t *             szCmdLine,
    __in    const wchar_t *       szCurrDir,
    __in    STARTUPINFOW &        si,
    __inout PROCESS_INFORMATION & pi,
    __inout std::wstringstream &       sErrorInfo)
{
    HANDLE hShellProcess = NULL, hShellProcessToken = NULL, hPrimaryToken = NULL;
    HWND hwnd = NULL;
    DWORD dwPID = 0;
    BOOL ret;
    DWORD dwLastErr;

    // Enable SeIncreaseQuotaPrivilege in this process. (This won't work if current process is not elevated.)
    HANDLE hProcessToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hProcessToken)) {
        dwLastErr = GetLastError();
        sErrorInfo << L"OpenProcessToken failed: " << SysErrorMessageWithCode(dwLastErr);
        return false;
    } else {
        TOKEN_PRIVILEGES tkp;
        tkp.PrivilegeCount = 1;
        LookupPrivilegeValue(NULL, SE_INCREASE_QUOTA_NAME, &tkp.Privileges[0].Luid);
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hProcessToken, FALSE, &tkp, 0, NULL, NULL);
        dwLastErr = GetLastError();
        CloseHandle(hProcessToken);
        if (ERROR_SUCCESS != dwLastErr) {
            sErrorInfo << L"AdjustTokenPrivileges failed: " << SysErrorMessageWithCode(dwLastErr);
            return false;
        }
    }

    // Get an HWND representing the desktop shell.
    // CAVEATS: This will fail if the shell is not running (crashed or terminated), or the default shell has been
    // replaced with a custom shell. This also won't return what you probably want if Explorer has been terminated and
    // restarted elevated.
    hwnd = GetShellWindow();
    if (NULL == hwnd) {
        sErrorInfo << L"No desktop shell is present";
        return false;
    }

    // Get the PID of the desktop shell process.
    GetWindowThreadProcessId(hwnd, &dwPID);
    if (0 == dwPID) {
        sErrorInfo << L"Unable to get PID of desktop shell.";
        return false;
    }

    // Open the desktop shell process in order to query it (get the token)
    hShellProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
    if (!hShellProcess) {
        dwLastErr = GetLastError();
        sErrorInfo << L"Can't open desktop shell process: " << SysErrorMessageWithCode(dwLastErr);
        return false;
    }

    // From this point down, we have handles to close, so make sure to clean up.

    bool retval = false;
    // Get the process token of the desktop shell.
    ret = OpenProcessToken(hShellProcess, TOKEN_DUPLICATE, &hShellProcessToken);
    if (!ret) {
        dwLastErr = GetLastError();
        sErrorInfo << L"Can't get process token of desktop shell: " << SysErrorMessageWithCode(dwLastErr);
        goto cleanup;
    }

    // Duplicate the shell's process token to get a primary token.
    // Based on experimentation, this is the minimal set of rights required for CreateProcessWithTokenW (contrary to current documentation).
    const DWORD dwTokenRights = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
    ret = DuplicateTokenEx(hShellProcessToken, dwTokenRights, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken);
    if (!ret) {
        dwLastErr = GetLastError();
        sErrorInfo << L"Can't get primary token: " << SysErrorMessageWithCode(dwLastErr);
        goto cleanup;
    }

    // Start the target process with the new token.
    ret = CreateProcessWithTokenW(
        hPrimaryToken,
        0,
        szApp,
        szCmdLine,
        0,
        NULL,
        szCurrDir,
        &si,
        &pi);
    if (!ret) {
        dwLastErr = GetLastError();
        sErrorInfo << L"CreateProcessWithTokenW failed: " << SysErrorMessageWithCode(dwLastErr);
        goto cleanup;
    }

    retval = true;

cleanup:
    // Clean up resources
    CloseHandle(hShellProcessToken);
    CloseHandle(hPrimaryToken);
    CloseHandle(hShellProcess);
    return retval;
}

void deelevate(const v8::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    String::Utf8Value exePathArg(args[0]);
    std::string exePath(*exePathArg);
    std::wstring w_exePath = s2ws(exePath);

    String::Utf8Value cmdLineArg(args[1]);
    std::string cmdLine(*cmdLineArg);
    std::wstring w_cmdLine = s2ws(cmdLine);

    // Build the sCmdLine argument and the other args needed for CreateProcessWithTokenW.
    std::wstringstream sCmdLine, sErrorInfo;
    sCmdLine << L"\"" << w_exePath << L"\" " << w_cmdLine;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SecureZeroMemory(&si, sizeof(si));
    SecureZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    // TODO:  casting sCmdLine.str().c_str() to a non-const is a little sloppy.  You can do better.
    if (RunAsDesktopUser(
      w_exePath.c_str(),
      (LPWSTR)sCmdLine.str().c_str(),
      NULL,
      si,
      pi,
      sErrorInfo))
    {
      // Make sure to close HANDLEs return in the PROCESS_INFORMATION.
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    } else {
      isolate->ThrowException(Exception::TypeError(
          String::NewFromUtf8(isolate, ws2s(sErrorInfo.str()).c_str())));
      return;
    }

    //args.GetReturnValue().Set(String::NewFromUtf8(isolate, "111"));
}

void elevate(const v8::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    String::Utf8Value exePathArg(args[0]);
    std::string exePath(*exePathArg);
    std::wstring w_exePath = s2ws(exePath);

    String::Utf8Value cmdLineArg(args[1]);
    std::string cmdLine(*cmdLineArg);
    std::wstring w_cmdLine = s2ws(cmdLine);

    SHELLEXECUTEINFO shExInfo = {0};
    shExInfo.cbSize = sizeof(shExInfo);
    shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExInfo.hwnd = 0;
    shExInfo.lpVerb = L"runas";
    shExInfo.lpFile = w_exePath.c_str();
    shExInfo.lpParameters = w_cmdLine.c_str();
    shExInfo.lpDirectory = 0;
    shExInfo.nShow = SW_SHOW;
    shExInfo.hInstApp = 0;

    if (ShellExecuteEx(&shExInfo)) {
        CloseHandle(shExInfo.hProcess);
        args.GetReturnValue().Set(Boolean::New(isolate, TRUE));
    } else {
        args.GetReturnValue().Set(Boolean::New(isolate, FALSE));
    }
}

void GetSystem32Path(const v8::FunctionCallbackInfo<Value>& args) {
    TCHAR szPath[MAX_PATH];
    Isolate* isolate = args.GetIsolate();

    if (FAILED(SHGetFolderPath(NULL, CSIDL_SYSTEM, NULL, 0, szPath)))
    {
      isolate->ThrowException(Exception::TypeError(
          String::NewFromUtf8(isolate, "Failed to retrieve a path")));
      return;
    }

#ifdef UNICODE
    std::vector<char> buffer;
    int size = WideCharToMultiByte(CP_UTF8, 0, szPath, -1, NULL, 0, NULL, NULL);
    if (size > 0) {
        buffer.resize(size);
        WideCharToMultiByte(CP_UTF8, 0, szPath, -1, &buffer[0], buffer.size(), NULL, NULL);
    }
    else {
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Failed to convert string")));
        return;
    }
    std::string string(&buffer[0]);
#else
    std::string string(szPath);
#endif

    args.GetReturnValue().Set(String::NewFromUtf8(isolate, string.c_str()));
}

void isUserAdmin(const v8::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    args.GetReturnValue().Set(Boolean::New(isolate, _isUserAdmin()));
}

void Init(Handle<Object> exports) {
    NODE_SET_METHOD(exports, "deelevate", deelevate);
    NODE_SET_METHOD(exports, "elevate", elevate);
    NODE_SET_METHOD(exports, "getSystem32Path", GetSystem32Path);
    NODE_SET_METHOD(exports, "isUserAdmin", isUserAdmin);
}

NODE_MODULE(winutils, Init)
