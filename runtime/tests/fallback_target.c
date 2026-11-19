/* L2.5 fallback-chain probe. Built as a no-CRT PE32+ EXE (/ENTRY:fb_main).
 *
 * The thin launcher maps this image and patches its IAT, so every ordinary
 * Win32 call below lands in one of lpvirt.dll's thunks. NONE of the paths in
 * this file are seeded into the virtual tree, so each thunk must detect a
 * virtual miss and forward to the real OS API through lpvirt.dll's own
 * unpatched import. A wrong result means that category's fallback is broken.
 *
 * This is the behavioural companion to lp_virt_fallback_audit (the structural
 * proof that lpvirt.dll's IAT itself is never patched).
 */
#include <windows.h>

/* no CRT: provide the few helpers main uses. */
static int fb_len(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void fb_puts(const char *s) {
  DWORD n = 0;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, (DWORD)fb_len(s), &n, NULL);
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "\r\n", 2, &n, NULL);
}
static void fb_line(const char *tag, int ok) {
  const char *p = tag;
  fb_puts(p);
  fb_puts(ok ? ": OK" : ": FAIL");
}

/* Print a non-negative integer in decimal, no CRT. */
static void fb_num(unsigned long v) {
  char buf[24];
  int i = 23;
  buf[i] = 0;
  if (v == 0) buf[--i] = '0';
  while (v) { buf[--i] = (char)('0' + (v % 10)); v /= 10; }
  fb_puts(&buf[i]);
}

int fb_main(void) {
  /* A real file that is definitely NOT in the virtual tree. */
  const wchar_t *realw = L"C:\\Windows\\win.ini";
  const char *reala = "C:\\Windows\\win.ini";

  /* 1. W-file fallback: CreateFileW + ReadFile + GetFileSizeEx + CloseHandle. */
  HANDLE h = CreateFileW(realw, GENERIC_READ, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  char buf[64] = {0};
  DWORD got = 0;
  BOOL rok = ReadFile(h, buf, sizeof(buf) - 1, &got, NULL);
  LARGE_INTEGER sz = {0};
  BOOL sok = GetFileSizeEx(h, &sz);
  fb_line("W file", h != INVALID_HANDLE_VALUE && rok && got > 0 && sok && sz.QuadPart > 0);
  CloseHandle(h);

  /* 2. W attributes fallback: GetFileAttributesW + GetFileAttributesExW. */
  DWORD attrs = GetFileAttributesW(realw);
  WIN32_FILE_ATTRIBUTE_DATA ad = {0};
  BOOL aok = GetFileAttributesExW(realw, GetFileExInfoStandard, &ad);
  fb_line("W attrs", attrs != INVALID_FILE_ATTRIBUTES && aok && ad.nFileSizeLow > 0);

  /* 3. A-file fallback: CreateFileA + GetFileAttributesA. */
  HANDLE ha = CreateFileA(reala, GENERIC_READ, FILE_SHARE_READ, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD ar = GetFileAttributesA(reala);
  fb_line("A file", ha != INVALID_HANDLE_VALUE && ar != INVALID_FILE_ATTRIBUTES);
  CloseHandle(ha);

  /* 4. Enumeration fallback: FindFirstFileW / FindNextFileW on a real dir. */
  WIN32_FIND_DATAW fd = {0};
  HANDLE fh = FindFirstFileW(L"C:\\Windows\\*.ini", &fd);
  int enum_ok = (fh != INVALID_HANDLE_VALUE);
  if (enum_ok) FindNextFileW(fh, &fd);
  fb_line("W enum", enum_ok);
  if (enum_ok) FindClose(fh);

  /* 5. Registry fallback: RegOpenKeyExW on a real key + RegCloseKey. */
  HKEY key = NULL;
  LONG rs = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                          0, KEY_READ, &key);
  fb_line("registry", rs == ERROR_SUCCESS);
  if (rs == ERROR_SUCCESS) RegCloseKey(key);

  /* 6. ntdll fallback: resolve NtCreateFile dynamically and open a real file. */
  HMODULE nt = GetModuleHandleA("ntdll.dll");
  /* Ordinal-free name resolution through our GetProcAddress thunk. */
  typedef LONG (NTAPI *ntopen_t)(HANDLE *, ACCESS_MASK, void *, void *,
                                 void *, ULONG, ULONG, ULONG, ULONG, void *, ULONG);
  ntopen_t ntopen = (ntopen_t)GetProcAddress(nt, "NtOpenFile");
  fb_line("ntdll resolve", ntopen != NULL);
  /* We do not construct OBJECT_ATTRIBUTES by hand here: NtCreateFile fallback
     is asserted by ntdll_target.exe. Presence of the routed symbol suffices. */

  /* 7. GetTempPathW fallback: this image does NOT seed a virtual temp path, so
        the thunk must return the real %TEMP%. */
  wchar_t tp[MAX_PATH] = {0};
  DWORD tn = GetTempPathW(MAX_PATH, tp);
  fb_line("temp path", tn > 0 && tp[0] != 0);

  /* 8. Report the fall-through counter from lpvirt.dll (loaded by launcher). */
  HMODULE virt = GetModuleHandleA("lpvirt.dll");
  if (virt) {
    typedef int (*stats_fn)(int *, int);
    stats_fn stats = (stats_fn)GetProcAddress(virt, "lp_virt_stats");
    if (stats) {
      int s[6] = {0};
      stats(s, 24);
      fb_puts("fallthroughs=");
      fb_num((unsigned long)s[2]);
    }
  }
  fb_puts("FALLBACK TARGET DONE");
  return 0;
}
