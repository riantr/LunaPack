/* Diagnostic only (L2.0): a normal CRT console EXE mapped by the thin launcher.
 *
 * This is NOT a passing gate. It characterizes the CRT-entry-point boundary:
 * a CRT main() eventually calls ExitProcess, which terminates the launcher
 * process too. The result is written to a real file named by the RESULT_FILE
 * environment variable so the outcome is observable even after ExitProcess.
 *
 * Build: cl /nologo /Fe:crt_target.exe crt_target.c /link kernel32.lib
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  const char *out = getenv("RESULT_FILE");
  FILE *f = out ? fopen(out, "w") : NULL;

  HANDLE h = CreateFileW(L"C:\\virt\\hello.txt", GENERIC_READ, FILE_SHARE_READ,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  char buf[128] = {0};
  DWORD got = 0;
  int ok = 0;
  if (h != INVALID_HANDLE_VALUE) {
    if (ReadFile(h, buf, sizeof(buf) - 1, &got, NULL)) {
      buf[got] = '\0';
      ok = (got == 13 && buf[0] == 'V' && buf[12] == 'K');
    }
    CloseHandle(h);
  }
  if (f) {
    fprintf(f, "CRT-EXE file=\"%s\" read=%lu ok=%d\n", buf, (unsigned long)got, ok);
    fclose(f);
  }
  printf("CRT-EXE file=\"%s\" ok=%d\n", buf, ok);
  return ok ? 0 : 1;
}
