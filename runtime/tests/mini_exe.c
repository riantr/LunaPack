/* Minimal PE32+ executable used by the L2.0 thin-launcher spike.
 *
 * Unlike payload.dll this is a real EXE image with an AddressOfEntryPoint,
 * not a DLL with exports. It is linked with /ENTRY:mini_main and
 * /NODEFAULTLIB: no CRT startup, no ExitProcess. That matters because the
 * thin launcher maps the image into its OWN process and calls the entry
 * point directly; a normal CRT entry would eventually call ExitProcess and
 * terminate the launcher too. CRT compatibility is an L3 item.
 *
 * The import table is deliberately built from the Win32 APIs the runtime
 * virtualizes, so the thin launcher's IAT patch has something to rewrite.
 * GetStdHandle is NOT hooked, so the status line goes to the real console
 * through the un-patched fallback - which exercises L1.6 as well.
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

int __cdecl mini_main(void) {
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  int ok = 0;

  HANDLE h = CreateFileW(L"C:\\virt\\hello.txt", GENERIC_READ, FILE_SHARE_READ,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    put(out, "THIN-EXE CreateFileW FAILED\n", 28);
    return 1;
  }

  char buf[128];
  DWORD got = 0;
  if (!ReadFile(h, buf, (DWORD)(sizeof(buf) - 1), &got, NULL)) {
    put(out, "THIN-EXE ReadFile FAILED\n", 25);
    CloseHandle(h);
    return 1;
  }
  buf[got] = '\0';

  LARGE_INTEGER size;
  int have_size = GetFileSizeEx(h, &size);
  DWORD attrs = GetFileAttributesW(L"C:\\virt\\hello.txt");
  CloseHandle(h);

  static const char expected[] = "VIRTUAL-FS-OK";
  if (got == sizeof(expected) - 1 && buf[0] == expected[0] && buf[1] == expected[1] &&
      buf[2] == expected[2] && buf[3] == expected[3] && buf[4] == expected[4] &&
      buf[5] == expected[5] && buf[6] == expected[6] && buf[7] == expected[7] &&
      buf[8] == expected[8] && buf[9] == expected[9] && buf[10] == expected[10] &&
      buf[11] == expected[11] && buf[12] == expected[12]) {
    ok = 1;
  }
  if (!have_size || size.QuadPart != 13) ok = 0;
  if (attrs != FILE_ATTRIBUTE_NORMAL) ok = 0;

  put(out, "THIN-EXE file=\"", 15);
  put(out, buf, (int)got);
  put(out, "\" size=", 8);
  putn(out, (unsigned long)size.QuadPart);
  put(out, " attrs=0x", 9);
  put(out, "80", 2);
  put(out, " result=", 8);
  put(out, ok ? "OK\n" : "FAIL\n", ok ? 3 : 5);

  /* L2.1: exercise ANSI variants through the mapped image's IAT. */
  DWORD a_attrs = GetFileAttributesA("C:\\virt\\ansi.txt");
  put(out, "THIN-EXE ansi attrs=0x", 22);
  put(out, a_attrs == FILE_ATTRIBUTE_NORMAL ? "80" : " bad ", 2);
  put(out, "\n", 1);

  HANDLE ah = CreateFileA("C:\\cfg\\fromansi.txt", GENERIC_WRITE, FILE_SHARE_READ,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (ah != INVALID_HANDLE_VALUE) {
    DWORD wrote = 0;
    WriteFile(ah, "ANSI-W", 6, &wrote, NULL);
    CloseHandle(ah);
    put(out, "THIN-EXE ansi create=", 21);
    put(out, "OK\n", 3);
  } else {
    put(out, "THIN-EXE ansi create=FAIL\n", 26);
    ok = 0;
  }
  if (a_attrs != FILE_ATTRIBUTE_NORMAL) ok = 0;

  /* L2.1: GetTempPathW returns the seeded virtual temp directory. */
  WCHAR tmp[MAX_PATH];
  DWORD tlen = GetTempPathW(MAX_PATH, tmp);
  /* Seeded L"C:\\virt\\tmp" with trailing separator -> "C:\\virt\\tmp\\" = 12 chars
     (GetTempPathW excludes the terminating NUL from its return value). */
  if (tlen == 12 && tmp[0] == 'C' && tmp[1] == ':' && tmp[2] == '\\' &&
      tmp[3] == 'v' && tmp[4] == 'i' && tmp[5] == 'r' && tmp[6] == 't' &&
      tmp[7] == '\\' && tmp[8] == 't' && tmp[9] == 'm' && tmp[10] == 'p' &&
      tmp[11] == '\\') {
    put(out, "THIN-EXE temp=OK\n", 17);
  } else {
    put(out, "THIN-EXE temp=FAIL\n", 19);
    ok = 0;
  }

  /* L2.2: dynamic resolution. GetProcAddress is itself a hooked slot, so it
   * returns our thunk for every virtualized API name. Verify by resolving
   * GetFileAttributesW dynamically and calling it on a virtual path. */
  static const char gpa_name[] = "GetFileAttributesW";
  HMODULE k32 = GetModuleHandleA("kernel32.dll");
  typedef DWORD(WINAPI *gfa_fn)(const wchar_t *);
  gfa_fn gfa = k32 ? (gfa_fn)GetProcAddress(k32, gpa_name) : 0;
  DWORD d_attrs = gfa ? gfa(L"C:\\virt\\hello.txt") : 0;
  put(out, "THIN-EXE dyn gpa attrs=0x", 25);
  put(out, d_attrs == FILE_ATTRIBUTE_NORMAL ? "80" : "bad ", 2);
  put(out, "\n", 1);
  if (d_attrs != FILE_ATTRIBUTE_NORMAL) ok = 0;

  /* L2.2: ordinal GetProcAddress must not fault. Ordinals are not virtualized;
   * they simply fall through to the real resolver. */
  FARPROC ord = k32 ? GetProcAddress(k32, (const char *)1) : 0;
  put(out, "THIN-EXE dyn ordinal=no-fault\n", 30);
  (void)ord;

  /* L2.2: LoadLibraryA is hooked. Loading dynlib.dll should patch that
   * module's static CreateFileW/ReadFile IAT; dyn_probe() can then read the
   * virtual file (impossible through the real API). */
  static const char dll_name[] = "dynlib.dll";
  typedef HMODULE(WINAPI *ll_fn)(const char *);
  typedef int(__cdecl *probe_fn)(void);
  ll_fn ll = k32 ? (ll_fn)GetProcAddress(k32, "LoadLibraryA") : 0;
  HMODULE dyn = ll ? ll(dll_name) : 0;
  if (dyn) {
    static const char probe_name[] = "dyn_probe";
    probe_fn probe = (probe_fn)GetProcAddress(dyn, probe_name);
    int dyn_ok = probe ? probe() : 0;
    put(out, "THIN-EXE dyn lib probe=", 23);
    put(out, dyn_ok == 1 ? "OK\n" : "FAIL\n", dyn_ok == 1 ? 3 : 5);
    if (dyn_ok != 1) ok = 0;
    FreeLibrary(dyn);
  } else {
    put(out, "THIN-EXE dyn lib load=FAIL\n", 27);
    ok = 0;
  }

  return ok ? 0 : 1;
}
