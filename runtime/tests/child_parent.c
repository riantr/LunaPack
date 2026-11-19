/* L0.4 spike — parent process with a local IAT hook on CreateProcessW
 * (throwaway C harness, not product code).
 *
 * The parent patches ONLY its own import address table — the same in-process
 * technique M0 uses for the 12 Win32 slots. When the program asks to start a
 * child, the hook rewrites the request to launch child_bootstrap.exe instead.
 * There is no CREATE_SUSPENDED, no WriteProcessMemory on another process, no
 * remote LoadLibrary, no OpenProcess with write rights. The child is started
 * with an ordinary CreateProcessW and inherits VFS state via environment.
 *
 * This directly tests the question the P0 injector could not answer: can a
 * child process be brought under the virtual FS without the injection API
 * family that Huorong quarantined 11 times?
 *
 * Usage: parent.exe <dist-dir> <payload-dll-name> <virtual-path> <virtual-data>
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef BOOL(WINAPI *create_process_w_fn)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
    DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static create_process_w_fn real_create_process = NULL;
static char g_bootstrap_path[MAX_PATH] = {0};
static char g_dist[MAX_PATH] = {0};
static char g_payload[128] = {0};

static BOOL WINAPI hooked_create_process(
    LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
    BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
  printf("PARENT intercepted CreateProcessW: cmd=%ls\n", cmd ? cmd : L"(null)");
  fflush(stdout);

  char new_cmd[1024];
  _snprintf_s(new_cmd, sizeof(new_cmd), _TRUNCATE,
              "\"%s\" \"%s\" \"%s\"", g_bootstrap_path, g_dist, g_payload);
  wchar_t new_cmd_w[1024];
  MultiByteToWideChar(CP_ACP, 0, new_cmd, -1, new_cmd_w, 1024);

  wprintf(L"PARENT redirect -> %s\n", new_cmd_w);
  fflush(stdout);
  return real_create_process(NULL, new_cmd_w, pa, ta, inherit, flags,
                             env, dir, si, pi);
}

/* Patch the CreateProcessW slot in this executable's OWN IAT.
 * Names are read from OriginalFirstThunk; the slot rewritten is FirstThunk.
 * After the loader binds, FirstThunk holds resolved addresses, not name RVAs. */
static int patch_own_iat(void) {
  HMODULE mod = GetModuleHandle(NULL);
  unsigned char *base = (unsigned char *)mod;
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

  IMAGE_DATA_DIRECTORY *imp_dir =
      &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!imp_dir->VirtualAddress) return 0;

  IMAGE_IMPORT_DESCRIPTOR *desc =
      (IMAGE_IMPORT_DESCRIPTOR *)(base + imp_dir->VirtualAddress);
  for (; desc->Name; desc++) {
    char *dll_name = (char *)(base + desc->Name);
    if (_stricmp(dll_name, "KERNEL32.dll") != 0 &&
        _stricmp(dll_name, "kernel32.dll") != 0) continue;

    ULONG_PTR *oft = (ULONG_PTR *)(base + desc->OriginalFirstThunk);
    ULONG_PTR *ft = (ULONG_PTR *)(base + desc->FirstThunk);
    for (; *oft; oft++, ft++) {
#ifdef _WIN64
      if (*oft & IMAGE_ORDINAL_FLAG64) continue;
#else
      if (*oft & IMAGE_ORDINAL_FLAG32) continue;
#endif
      IMAGE_IMPORT_BY_NAME *by_name = (IMAGE_IMPORT_BY_NAME *)(base + *oft);
      if (strcmp((char *)by_name->Name, "CreateProcessW") != 0) continue;

      DWORD old = 0;
      if (!VirtualProtect(ft, sizeof(void *), PAGE_READWRITE, &old)) return 0;
      real_create_process = (create_process_w_fn)(void *)*ft;
      *ft = (ULONG_PTR)(void *)hooked_create_process;
      DWORD tmp = 0;
      VirtualProtect(ft, sizeof(void *), old, &tmp);
      return 1;
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc < 5) {
    printf("usage: parent.exe <dist> <payload-name> <virtual-path> <virtual-data>\n");
    return 1;
  }
  strncpy_s(g_dist, sizeof(g_dist), argv[1], _TRUNCATE);
  strncpy_s(g_payload, sizeof(g_payload), argv[2], _TRUNCATE);
  _snprintf_s(g_bootstrap_path, sizeof(g_bootstrap_path), _TRUNCATE,
              "%s\\child_bootstrap.exe", argv[1]);

  /* VFS state travels with the child through inherited environment variables. */
  SetEnvironmentVariableA("LUNAPACK_VFS_PATH", argv[3]);
  SetEnvironmentVariableA("LUNAPACK_VFS_DATA", argv[4]);

  if (!patch_own_iat()) {
    printf("PARENT ERROR could not patch own CreateProcessW IAT\n");
    return 2;
  }
  printf("PARENT pid=%lu own CreateProcessW IAT patched\n",
         (unsigned long)GetCurrentProcessId());

  wchar_t target[] = L"C:\\virt\\pretend-child.exe";
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  ZeroMemory(&pi, sizeof(pi));
  si.cb = sizeof(si);
  BOOL ok = CreateProcessW(NULL, target, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
  if (!ok) {
    printf("PARENT ERROR CreateProcessW failed gle=%lu\n", GetLastError());
    return 3;
  }
  printf("PARENT child pid=%lu started by ordinary CreateProcessW\n",
         (unsigned long)pi.dwProcessId);
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  printf("PARENT child exit code=%lu\n", (unsigned long)code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return code == 0 ? 0 : 4;
}
