/* L2.6 end-to-end fixture: a child cmd.exe has to read a virtual file.
 *
 * cmd.exe resolves `type C:\virt\hello.txt` through SearchPathW before it
 * opens the file. The Win32 open side is already virtualized, so a failure
 * here can only be the resolution gap - or a child that never started. The
 * control `echo` run separates those two cases.
 *
 * Built without the CRT: the only APIs used are the ones whose IAT slots are
 * under test, plus the console handle used for the status line.
 */
#include <windows.h>

static void put(HANDLE h, const char *s, int n) {
  DWORD wrote = 0;
  WriteFile(h, s, (DWORD)n, &wrote, NULL);
}

static void putn(HANDLE h, unsigned long v) {
  char b[16];
  int i = 15;
  b[15] = ' ';
  if (v == 0) { b[14] = '0'; i = 14; }
  while (v != 0) { b[--i] = (char)('0' + (v % 10)); v /= 10; }
  put(h, b + i, 16 - i);
}

static int spawn_cmd(WCHAR *line, HANDLE out, DWORD *code) {
  static const WCHAR app[] = L"C:\\Windows\\System32\\cmd.exe";
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  BOOL ok;
  int i;
  for (i = 0; i < (int)sizeof(si); i++) ((char *)&si)[i] = 0;
  for (i = 0; i < (int)sizeof(pi); i++) ((char *)&pi)[i] = 0;
  si.cb = sizeof(si);
  ok = CreateProcessW(app, line, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
  if (!ok) {
    put(out, "CMD-PROBE create=FAIL err=", 26);
    putn(out, (unsigned long)GetLastError());
    put(out, "\n", 1);
    return 0;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  GetExitCodeProcess(pi.hProcess, code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return 1;
}

int __cdecl cmdsearch_main(void) {
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  WCHAR control[] = L"cmd.exe /c echo CMD-PROBE-CONTROL-OK";
  WCHAR exists[] = L"cmd.exe /c if exist C:\\virt\\hello.txt echo CMD-PROBE-EXIST-OK";
  WCHAR target[] = L"cmd.exe /c type C:\\virt\\hello.txt";
  DWORD code = 0;
  int ok = 1;

  if (spawn_cmd(control, out, &code) && code == 0) {
    put(out, "CMD-PROBE control=OK\n", 21);
  } else {
    put(out, "CMD-PROBE control=FAIL\n", 23);
    ok = 0;
  }

  /* Existence is answered by GetFileAttributesW; reading is answered by CRT
   * stdio. Splitting the two tells L2.6 from L2.7 without guessing. */
  if (spawn_cmd(exists, out, &code) && code == 0) {
    put(out, "CMD-PROBE exist=OK\n", 19);
  } else {
    put(out, "CMD-PROBE exist=FAIL\n", 21);
    ok = 0;
  }

  if (!spawn_cmd(target, out, &code)) {
    ok = 0;
  } else {
    put(out, "CMD-PROBE child=OK code=", 24);
    putn(out, (unsigned long)code);
    put(out, "\n", 1);
    if (code != 0) ok = 0;
  }

  put(out, "CMD-PROBE result=", 17);
  put(out, ok ? "OK\n" : "FAIL\n", ok ? 3 : 5);
  return ok ? 0 : 2;
}
