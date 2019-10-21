#pragma once

// Structure and operators to insert a zero-filled hex-formatted number into a std::ostream.
struct HEX {
  HEX(unsigned long num, unsigned long fieldwidth = 8, bool bUpcase = false)
    : m_num(num), m_width(fieldwidth), m_upcase(bUpcase)
    {}

  unsigned long m_num;
  unsigned long m_width;
  bool m_upcase;
};

inline std::ostream& operator << (std::ostream& os, const HEX & h) {
  int fmt = os.flags();
  char fillchar = os.fill('0');
  os << "0x" << std::hex << (h.m_upcase ? std::uppercase : std::nouppercase) << std::setw(h.m_width) << h.m_num;
  os.fill(fillchar);
  os.flags(fmt);
  return os;
}

inline std::wostream& operator << (std::wostream& os, const HEX & h) {
  int fmt = os.flags();
  wchar_t fillchar = os.fill(L'0');
  os << L"0x" << std::hex << (h.m_upcase ? std::uppercase : std::nouppercase) << std::setw(h.m_width) << h.m_num;
  os.fill(fillchar);
  os.flags(fmt);
  return os;
}

// Convert an error code to corresponding text, returning it as a std::wstring.

inline std::wstring SysErrorMessageWithCode(DWORD dwErrCode /*= GetLastError()*/) {
  LPWSTR pszErrMsg = NULL;
  std::wstringstream sRetval;
  DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM;

  if(
    FormatMessageW(
      flags,
      NULL,
      dwErrCode,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
      (LPWSTR) &pszErrMsg,
      0,
      NULL
    )
  ) {
    sRetval << pszErrMsg << L" (Error # " << dwErrCode << L" = " << HEX(dwErrCode) << L")";
    LocalFree(pszErrMsg);
  } else {
    sRetval << L"Error # " << dwErrCode << L" (" << HEX(dwErrCode) << L")";
  }

  return sRetval.str();
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

// Convert std::wstring to std::string
std::string ws2s(const std::wstring &s) {
  int len;
  int slength = (int)s.length() + 1;
  len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), slength, 0, 0, 0, 0);
  char* buf = new char[len];
  WideCharToMultiByte(CP_UTF8, 0, s.c_str(), slength, buf, len, 0, 0);
  std::string r(buf);
  delete[] buf;
  return r;
}
