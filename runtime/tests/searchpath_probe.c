/* L2.6 negative fixture: does path resolution reach the virtual filesystem?
 *
 * A mapped program can open C:\virt\hello.txt through CreateFileW today. The
 * same path asked of SearchPathW still fails, because cmd.exe resolves a path
 * before it opens it and SearchPathW is not in hook_table(). This probe is
 * built without the CRT so the only thing under test is the Win32 boundary.
 *
 * It checks four properties of the W and A forms:
 *   - a virtual absolute path resolves to a usable path
 *   - lpFilePart points at the file name inside the returned buffer
 *   - a too-small buffer returns the required size, as Win32 does
 *   - a real system DLL still resolves through the unhooked fallback
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

static int lower_a(char c) {
  return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static int equal_a(const char *a, const char *b, int n) {
  int i;
  for (i = 0; i < n; i++) {
    if (lower_a(a[i]) != lower_a(b[i])) return 0;
  }
  return 1;
}

static int equal_w(const WCHAR *a, const WCHAR *b, int n) {
  int i;
  for (i = 0; i < n; i++) {
    WCHAR x = a[i];
    WCHAR y = b[i];
    if (x >= L'A' && x <= L'Z') x = (WCHAR)(x + (L'a' - L'A'));
    if (y >= L'A' && y <= L'Z') y = (WCHAR)(y + (L'a' - L'A'));
    if (x != y) return 0;
  }
  return 1;
}

int __cdecl searchpath_main(void) {
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  int ok = 1;
  int i;
  static const WCHAR wanted[] = L"C:\\virt\\hello.txt";
  static const WCHAR leaf[] = L"hello.txt";
  static const char wanted_a[] = "C:\\virt\\hello.txt";
  static const char leaf_a[] = "hello.txt";
  WCHAR wide[256];
  WCHAR shortbuf[8];
  WCHAR *part = NULL;
  DWORD n;

  for (i = 0; i < 256; i++) wide[i] = 0;
  for (i = 0; i < 8; i++) shortbuf[i] = 0;
  n = SearchPathW(NULL, wanted, NULL, 256, wide, &part);
  if (n == 17 && equal_w(wide, wanted, 17)) {
    put(out, "SEARCH-W hit=OK\n", 16);
  } else {
    put(out, "SEARCH-W hit=FAIL n=", 20);
    putn(out, n);
    put(out, "\n", 1);
    ok = 0;
  }
  if (part != NULL && part >= wide && part < wide + 256 &&
      (DWORD)(part - wide) == 8 && equal_w(part, leaf, 9)) {
    put(out, "SEARCH-W part=OK\n", 17);
  } else {
    put(out, "SEARCH-W part=FAIL\n", 19);
    ok = 0;
  }

  n = SearchPathW(NULL, wanted, NULL, 4, shortbuf, &part);
  if (n >= 18) {
    put(out, "SEARCH-W small=OK\n", 18);
  } else {
    put(out, "SEARCH-W small=FAIL n=", 22);
    putn(out, n);
    put(out, "\n", 1);
    ok = 0;
  }

  {
    char ansi[256];
    char *apart = NULL;
    DWORD an;
    for (i = 0; i < 256; i++) ansi[i] = 0;
    an = SearchPathA(NULL, wanted_a, NULL, 256, ansi, &apart);
    if (an == 17 && equal_a(ansi, wanted_a, 17)) {
      put(out, "SEARCH-A hit=OK\n", 16);
    } else {
      put(out, "SEARCH-A hit=FAIL n=", 20);
      putn(out, an);
      put(out, "\n", 1);
      ok = 0;
    }
    if (apart != NULL && apart >= ansi && apart < ansi + 256 &&
        (DWORD)(apart - ansi) == 8 && equal_a(apart, leaf_a, 9)) {
      put(out, "SEARCH-A part=OK\n", 17);
    } else {
      put(out, "SEARCH-A part=FAIL\n", 19);
      ok = 0;
    }
  }

  {
    WCHAR realbuf[512];
    WCHAR *rpart = NULL;
    DWORD rn;
    for (i = 0; i < 512; i++) realbuf[i] = 0;
    rn = SearchPathW(NULL, L"kernel32.dll", NULL, 512, realbuf, &rpart);
    if (rn > 0 && rn < 512 && rpart != NULL) {
      put(out, "SEARCH-W real=OK\n", 17);
    } else {
      put(out, "SEARCH-W real=FAIL\n", 19);
      ok = 0;
    }
  }

  /* The path SearchPathW handed back has to be the one CreateFileW can open. */
  {
    HANDLE h = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
      char data[32];
      DWORD got = 0;
      int read_ok;
      for (i = 0; i < 32; i++) data[i] = 0;
      read_ok = ReadFile(h, data, 13, &got, NULL) && got == 13 &&
                equal_a(data, "VIRTUAL-FS-OK", 13);
      CloseHandle(h);
      if (read_ok) {
        put(out, "SEARCH-W read=OK\n", 17);
      } else {
        put(out, "SEARCH-W read=FAIL\n", 19);
        ok = 0;
      }
    } else {
      put(out, "SEARCH-W read=FAIL\n", 19);
      ok = 0;
    }
  }

  put(out, "SEARCH result=", 14);
  put(out, ok ? "OK\n" : "FAIL\n", ok ? 3 : 5);
  return ok ? 0 : 1;
}
