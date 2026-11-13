/* Consumer used by the runtime harness. It is deliberately ordinary: it
   calls the normal Win32 file and registry APIs and knows nothing about
   virtualization or about the fact that it was mapped from memory rather
   than loaded by the OS loader.

   Build it as a DLL. `lp_payload_run` is the entry the host looks up in the
   mapped image. */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef HANDLE (WINAPI *create_file_w_fn)(LPCWSTR, DWORD, DWORD,
                                          LPSECURITY_ATTRIBUTES, DWORD,
                                          DWORD, HANDLE);

/* The harness sets this to the path of a REAL file, to prove that requests
   we do not own fall through to the OS. Keeping it out of the source means
   this file has no machine-specific paths in it. */
static void real_file_path(WCHAR *out, DWORD cap) {
  char a[MAX_PATH];
  DWORD n = GetEnvironmentVariableA("LUNAPACK_REAL_FILE", a, MAX_PATH);
  DWORD i;
  if (n == 0 || n >= cap) { out[0] = 0; return; }
  for (i = 0; i < n; i++) out[i] = (WCHAR)(unsigned char)a[i];
  out[n] = 0;
}

__declspec(dllexport)
int lp_payload_run(char *out, int cap) {
  int used = 0;
#define EMIT(...) used += snprintf(out + used, (size_t)(cap - used), __VA_ARGS__)

  /* 1. A virtual file: the bytes must come from memory. */
  HANDLE h = CreateFileW(L"C:\\virt\\hello.txt", GENERIC_READ,
                         FILE_SHARE_READ, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
  char vbuf[64] = {0};
  DWORD got = 0;
  BOOL ok = ReadFile(h, vbuf, (DWORD)sizeof(vbuf) - 1, &got, NULL);
  LARGE_INTEGER vsize = {0};
  GetFileSizeEx(h, &vsize);
  DWORD vattrs = GetFileAttributesW(L"C:\\virt\\hello.txt");
  EMIT("virtual file : handle=%p read=%d bytes=%lu size=%lld attrs=0x%lx data=\"%s\"\n",
       (void *)h, (int)ok, (unsigned long)got, (long long)vsize.QuadPart,
       (unsigned long)vattrs, vbuf);
  CloseHandle(h);

  /* 2. A real file: the thunk must fall through to the real CreateFileW. */
  WCHAR realW[MAX_PATH];
  real_file_path(realW, MAX_PATH);
  HANDLE rh = CreateFileW(realW, GENERIC_READ, FILE_SHARE_READ, NULL,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  char rbuf[64] = {0};
  DWORD rgot = 0;
  BOOL rok = ReadFile(rh, rbuf, (DWORD)sizeof(rbuf) - 1, &rgot, NULL);
  EMIT("real file    : handle=%p read=%d bytes=%lu data=\"%s\"\n",
       (void *)rh, (int)rok, (unsigned long)rgot, rbuf);
  CloseHandle(rh);

  /* 3. Directory enumeration from the memory tree. */
  WIN32_FIND_DATAW fd;
  HANDLE hf = FindFirstFileW(L"C:\\virt\\*.txt", &fd);
  if (hf != INVALID_HANDLE_VALUE) {
    EMIT("virtual enum : first=\"%ls\"", fd.cFileName);
    while (FindNextFileW(hf, &fd)) {
      EMIT(", \"%ls\"", fd.cFileName);
    }
    EMIT("\n");
    /* No FindClose: the handle is a virtual pseudo-handle. */
  } else {
    EMIT("virtual enum : none\n");
  }

  /* 4. HKLM read from the virtual hive. */
  HKEY key = NULL;
  LONG st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\LunaPack", 0,
                          KEY_READ | KEY_WRITE, &key);
  WCHAR product[128] = {0};
  DWORD ptype = 0, psize = sizeof(product);
  LONG qs = RegQueryValueExW(key, L"Product", NULL, &ptype,
                             (LPBYTE)product, &psize);
  EMIT("registry     : open=%ld query=%ld type=%lu value=\"%ls\"\n",
       (long)st, (long)qs, (unsigned long)ptype, product);

  /* 5. HKLM write without administrator rights, then read it back. */
  DWORD ver = 42;
  LONG ws = RegSetValueExW(key, L"Version", 0, REG_DWORD,
                           (const BYTE *)&ver, sizeof(ver));
  DWORD back = 0, btype = 0, bsize = sizeof(back);
  LONG qs2 = RegQueryValueExW(key, L"Version", NULL, &btype,
                              (LPBYTE)&back, &bsize);
  EMIT("registry set : status=%ld read=%ld type=%lu dword=%lu\n",
       (long)ws, (long)qs2, (unsigned long)btype, (unsigned long)back);
  RegCloseKey(key);

  /* 6. A real registry key must still fall through. */
  HKEY realkey = NULL;
  LONG rs = RegOpenKeyExW(HKEY_CURRENT_USER,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                          0, KEY_READ, &realkey);
  EMIT("real registry: open=%ld (fall-through)\n", (long)rs);
  if (rs == ERROR_SUCCESS) RegCloseKey(realkey);

  /* 7. Dynamic resolution: GetProcAddress("CreateFileW") must be hooked too. */
  HMODULE k32 = GetModuleHandleA("kernel32.dll");
  create_file_w_fn dyn = (create_file_w_fn)(void *)GetProcAddress(k32, "CreateFileW");
  HANDLE dh = dyn(L"C:\\virt\\dynamic.txt", GENERIC_READ, FILE_SHARE_READ,
                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  char dbuf[32] = {0};
  DWORD dgot = 0;
  ReadFile(dh, dbuf, (DWORD)sizeof(dbuf) - 1, &dgot, NULL);
  EMIT("dynamic hook : data=\"%s\"\n", dbuf);
  CloseHandle(dh);
#undef EMIT
  return used;
}
