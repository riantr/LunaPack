/* L4/Tier-B probe: does a CRT-mediated read reach the virtual filesystem?
 *
 * Every fixture so far calls CreateFileW itself, so the virtual layer only had
 * to answer a Win32 import of the mapped image. A program built the ordinary
 * way reads through its CRT, and `fopen` lives in msvcrt/ucrtbase - a system
 * DLL this runtime deliberately does not patch. This probe is the smallest
 * thing that can tell those two paths apart: it opens the same virtual file
 * twice, once through stdio and once through Win32.
 *
 * Expected under full coverage: both lines say OK. The interesting case is
 * `crthelp` failing while `win32` succeeds.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void) {
  FILE *f = fopen("C:\\virt\\hello.txt", "rb");
  if (f == NULL) {
    printf("C-open  result=FAILED\n");
  } else {
    char buf[64] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    printf("C-open  result=OK n=%u data=\"%s\"\n", (unsigned)n, buf);
  }

  HANDLE h = CreateFileW(
      L"C:\\virt\\hello.txt", GENERIC_READ, FILE_SHARE_READ, NULL,
      OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    printf("win32   result=FAILED\n");
    return 3;
  }
  char data[64] = {0};
  DWORD got = 0;
  BOOL ok = ReadFile(h, data, (DWORD)(sizeof(data) - 1), &got, NULL);
  CloseHandle(h);
  printf("win32   result=%s data=\"%s\"\n", ok ? "OK" : "FAILED", data);
  return ok ? 0 : 4;
}
