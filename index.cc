#include <node.h>
#include "Windows.h"

using v8::Isolate;
using v8::String;
using v8::Object;
using v8::Boolean;

// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
BOOL _isUserAdmin() {
  SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
  PSID AdministratorsGroup;

  BOOL b = AllocateAndInitializeSid(
    &NtAuthority,
    2,
    SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS,
    0, 0, 0, 0, 0, 0,
    &AdministratorsGroup
  );

  if(b) {
    if(!CheckTokenMembership(NULL, AdministratorsGroup, &b)) {
      b = false;
    }

    FreeSid(AdministratorsGroup);
  }

  return b;
}

// Convert std::string to std::wstring
std::wstring s2ws(const std::string &s) {
  int len;
  int slength = (int)s.length() + 1;
  len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), slength, 0, 0);
  wchar_t* buf = new wchar_t[len];
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), slength, buf, len);
  std::wstring r(buf);
  delete[] buf;
  return r;
}

void isUserAdmin(const v8::FunctionCallbackInfo<v8::Value> &args) {
  Isolate *isolate = args.GetIsolate();

  args.GetReturnValue().Set(Boolean::New(isolate, _isUserAdmin()));
}

void elevate(const v8::FunctionCallbackInfo<v8::Value> &args) {
  Isolate* isolate = args.GetIsolate();

  String::Utf8Value exePathArg(isolate, args[0]);
  std::string exePath(*exePathArg);
  std::wstring w_exePath = s2ws(exePath);

  String::Utf8Value cmdLineArg(isolate, args[1]);
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

  if(ShellExecuteEx(&shExInfo)) {
    CloseHandle(shExInfo.hProcess);
    args.GetReturnValue().Set(Boolean::New(isolate, TRUE));
  } else {
    args.GetReturnValue().Set(Boolean::New(isolate, FALSE));
  }
}

void Init(v8::Local<Object> exports) {
  NODE_SET_METHOD(exports, "isUserAdmin", isUserAdmin);
  NODE_SET_METHOD(exports, "elevate", elevate);
}

NODE_MODULE(winutils, Init)
