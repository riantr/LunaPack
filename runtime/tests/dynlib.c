/* L2.2 dynamic-resolution test double: a DLL loaded at RUNTIME by the mapped
 * EXE through the hooked LoadLibraryA.
 *
 * The point of this DLL is its import table: CreateFileW / ReadFile /
 * CloseHandle are static imports. When the launcher's hook calls
 * patch_loaded_module() on the HMODULE returned by the real loader, those
 * three IAT slots are rewritten to our thunks. dyn_probe() then reads the
 * virtual file created by the launcher, which is only possible if the patch
 * took effect - the real CreateFileW cannot see the in-memory VFS.
 */
#include <windows.h>

__declspec(dllexport) int __cdecl dyn_probe(void) {
  HANDLE h = CreateFileW(L"C:\\virt\\hello.txt", GENERIC_READ, FILE_SHARE_READ,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  char buf[64];
  DWORD got = 0;
  if (!ReadFile(h, buf, (DWORD)(sizeof(buf) - 1), &got, NULL)) {
    CloseHandle(h);
    return 0;
  }
  CloseHandle(h);
  buf[got] = '\0';
  /* "VIRTUAL-FS-OK" is 13 bytes; checking the head keeps this CRT-free. */
  if (got == 13 && buf[0] == 'V' && buf[1] == 'I' && buf[2] == 'R') return 1;
  return 0;
}
