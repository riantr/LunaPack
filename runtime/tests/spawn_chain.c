/* L4 test target: a program that reads a virtual file and then starts another
 * copy of itself.
 *
 * It is deliberately built without the CRT so the mapped image has an entry
 * point we can call directly, the same shape as mini_target.c and
 * ntdll_target.c. That means no printf and no atoi: output goes through
 * WriteFile and numbers are formatted by hand.
 *
 * The point of the test is the chain:
 *   launcher(level 1) -> launcher(level 2) -> launcher(level 3)
 * Each level must read the same virtual file, which can only happen if the
 * virtual tree crossed two process boundaries. The level is carried in
 * LUNAPACK_TEST_LEVEL and the program to start in LUNAPACK_TEST_CHILD, both
 * inherited through the environment block the redirect builds.
 */
#include <windows.h>

static void put(const char *s, int n) {
  DWORD wrote = 0;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, (DWORD)n, &wrote, NULL);
}

static void say(const char *s) { put(s, lstrlenA(s)); }

static void say_int(int v) {
  char buf[12];
  int i = 0;
  unsigned int u;
  if (v < 0) {
    put("-", 1);
    u = (unsigned int)(-v);
  } else {
    u = (unsigned int)v;
  }
  if (u == 0) {
    put("0", 1);
    return;
  }
  while (u > 0 && i < (int)sizeof(buf)) {
    buf[i++] = (char)('0' + (u % 10));
    u /= 10;
  }
  while (i > 0) {
    put(&buf[--i], 1);
  }
}

static int parse_int(const char *s) {
  int v = 0;
  while (*s >= '0' && *s <= '9') {
    v = v * 10 + (*s - '0');
    s++;
  }
  return v;
}

static int read_virtual(const wchar_t *path, char *buf, int cap) {
  HANDLE h = CreateFileW(
      path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
      OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    return 0;
  }
  DWORD got = 0;
  BOOL ok = ReadFile(h, buf, (DWORD)(cap - 1), &got, NULL);
  CloseHandle(h);
  if (!ok) {
    return 0;
  }
  buf[got] = 0;
  return 1;
}

/* ZeroMemory can compile to a memset call, which a /NODEFAULTLIB image does
 * not have. Four stores per iteration is enough for two STARTUPINFO-sized
 * structs and keeps the link free of CRT symbols. */
static void clear(void *p, unsigned int n) {
  unsigned char *b = (unsigned char *)p;
  for (unsigned int i = 0; i < n; i++) {
    b[i] = 0;
  }
}

static void widen(const char *a, wchar_t *w, int cap) {
  int i = 0;
  while (a[i] && i < cap - 1) {
    w[i] = (wchar_t)(unsigned char)a[i];
    i++;
  }
  w[i] = 0;
}

int spawn_main(void) {
  char text[16] = {0};
  int level = 1;
  if (GetEnvironmentVariableA("LUNAPACK_TEST_LEVEL", text, sizeof(text)) > 0) {
    level = parse_int(text);
  }

  char data[256] = {0};
  int got = read_virtual(L"C:\\virt\\hello.txt", data, sizeof(data));
  say("SPAWN level=");
  say_int(level);
  say(got ? " virtual read=OK data=\"" : " virtual read=FAILED data=\"");
  say(got ? data : "");
  say("\"\n");

  char child[MAX_PATH] = {0};
  if (GetEnvironmentVariableA("LUNAPACK_TEST_CHILD", child, sizeof(child)) == 0 ||
      level >= 3) {
    say("SPAWN chain end\n");
    return got ? 0 : 3;
  }

  /* The next level is told which level it is before it starts, so the value is
     in this process environment when the redirect copies it into the child's
     block. */
  char next[16];
  {
    int n = level + 1, i = 0;
    char tmp[12];
    while (n > 0 && i < (int)sizeof(tmp)) {
      tmp[i++] = (char)('0' + (n % 10));
      n /= 10;
    }
    int j = 0;
    while (i > 0) {
      next[j++] = tmp[--i];
    }
    next[j] = 0;
  }
  SetEnvironmentVariableA("LUNAPACK_TEST_LEVEL", next);

  char cmd[MAX_PATH + 8];
  {
    int i = 0;
    cmd[i++] = '"';
    for (int k = 0; child[k] && i < (int)sizeof(cmd) - 3; k++) {
      cmd[i++] = child[k];
    }
    cmd[i++] = '"';
    cmd[i] = 0;
  }
  wchar_t wcmd[MAX_PATH + 8];
  widen(cmd, wcmd, MAX_PATH + 8);

  say("SPAWN level=");
  say_int(level);
  say(" starting level ");
  say_int(level + 1);
  say("\n");

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  clear(&si, (unsigned int)sizeof(si));
  clear(&pi, (unsigned int)sizeof(pi));
  si.cb = sizeof(si);
  if (!CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
    say("SPAWN level=");
    say_int(level);
    say(" spawn FAILED\n");
    return 4;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  say("SPAWN level=");
  say_int(level);
  say(" child exit=");
  say_int((int)code);
  say("\n");
  return (int)code;
}
