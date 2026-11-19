/* L0.4 spike — child-side bootstrap (throwaway C harness, not product code).
 *
 * The child is launched by an ORDINARY CreateProcess from the parent. It does
 * NOT receive an injected thread, a suspended process, or a remote
 * WriteProcessMemory/LoadLibrary. It loads lpvirt.dll into ITS OWN process,
 * seeds the VFS from environment variables inherited at process creation,
 * maps a payload DLL from memory, patches that module's IAT, and runs it.
 *
 * This is the same pattern M0 (host.c) already proved AV-clean; the only new
 * elements are (a) running in a child process and (b) inheriting VFS state
 * across the process boundary via environment variables.
 *
 * Usage: bootstrap.exe <dist-dir> [payload-dll-name]
 * Env:   LUNAPACK_VFS_PATH, LUNAPACK_VFS_DATA
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef void (*init_fn)(void);
typedef void (*reset_fn)(void);
typedef int (*add_file_fn)(const wchar_t *, const void *, int);
typedef int (*install_fn)(int64_t);
typedef int64_t (*map_fn)(const void *, int32_t);
typedef int32_t (*map_error_fn)(void);
typedef int64_t (*get_export_fn)(int64_t, const char *);
typedef int64_t (*get_entry_fn)(int64_t);
typedef int32_t (*unmap_fn)(int64_t);
typedef BOOL(WINAPI *dll_main_fn)(HINSTANCE, DWORD, LPVOID);
typedef int (*payload_fn)(char *, int);

#define GET(h, name, type) (type)(void *)GetProcAddress(h, name)

static void wide_from_ascii(const char *a, wchar_t *w, int cap) {
  int i = 0;
  while (*a && i < cap - 1) { w[i++] = (wchar_t)(unsigned char)*a++; }
  w[i] = 0;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  const char *dir = argc > 1 ? argv[1] : ".";
  const char *payload_name = argc > 2 ? argv[2] : "payload.dll";
  char dll_path[MAX_PATH], payload_path[MAX_PATH];
  char vpath[512], vdata[512];
  _snprintf_s(dll_path, sizeof(dll_path), _TRUNCATE, "%s\\lpvirt.dll", dir);
  _snprintf_s(payload_path, sizeof(payload_path), _TRUNCATE, "%s\\%s", dir, payload_name);

  DWORD np = GetEnvironmentVariableA("LUNAPACK_VFS_PATH", vpath, sizeof(vpath));
  DWORD nd = GetEnvironmentVariableA("LUNAPACK_VFS_DATA", vdata, sizeof(vdata));
  if (!np || !nd) {
    printf("BOOTSTRAP pid=%lu ERROR missing inherited VFS env\n", GetCurrentProcessId());
    return 2;
  }
  printf("BOOTSTRAP pid=%lu vfs_path=%s vfs_data=%s\n",
         (unsigned long)GetCurrentProcessId(), vpath, vdata);

  HMODULE virt = LoadLibraryA(dll_path);
  if (!virt) {
    printf("BOOTSTRAP ERROR LoadLibrary lpvirt gle=%lu\n", GetLastError());
    return 3;
  }
  init_fn init = GET(virt, "moonbit_init", init_fn);
  reset_fn reset = GET(virt, "lp_virt_reset", reset_fn);
  add_file_fn add_file = GET(virt, "lp_virt_add_file", add_file_fn);
  install_fn install = GET(virt, "lp_install_iat_hooks", install_fn);
  map_fn map_image = GET(virt, "lp_map_image", map_fn);
  map_error_fn map_error = GET(virt, "lp_map_error", map_error_fn);
  get_export_fn get_export = GET(virt, "lp_get_export", get_export_fn);
  get_entry_fn get_entry = GET(virt, "lp_get_entry", get_entry_fn);
  unmap_fn unmap_image = GET(virt, "lp_unmap_image", unmap_fn);
  if (!init || !reset || !add_file || !install || !map_image || !map_error ||
      !get_export || !get_entry || !unmap_image) {
    printf("BOOTSTRAP ERROR missing export in lpvirt.dll\n");
    return 4;
  }

  init();
  reset();
  wchar_t wpath[512];
  wide_from_ascii(vpath, wpath, 512);
  int seeded = add_file(wpath, vdata, (int)strlen(vdata));
  printf("BOOTSTRAP seeded virtual file status=%d\n", seeded);

  FILE *f = fopen(payload_path, "rb");
  if (!f) { printf("BOOTSTRAP ERROR cannot read payload (%s)\n", payload_path); return 5; }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char *image = (unsigned char *)malloc((size_t)size);
  if (!image || fread(image, 1, (size_t)size, f) != (size_t)size) {
    printf("BOOTSTRAP ERROR short read\n"); fclose(f); return 6;
  }
  fclose(f);
  printf("BOOTSTRAP payload bytes=%ld\n", size);

  int64_t base = map_image(image, (int32_t)size);
  if (!base) {
    printf("BOOTSTRAP ERROR map failed reason=%ld\n", (long)map_error());
    free(image); return 7;
  }
  printf("BOOTSTRAP mapped base=0x%016llx\n", (unsigned long long)base);
  printf("BOOTSTRAP OS loader knows payload: %s\n",
         GetModuleHandleW(L"payload.dll") ? "YES (unexpected)" : "NO (expected)");

  int64_t entry = get_entry(base);
  dll_main_fn dm = NULL;
  if (entry) {
    dm = (dll_main_fn)(void *)(intptr_t)entry;
    dm((HINSTANCE)(intptr_t)base, DLL_PROCESS_ATTACH, NULL);
  }
  int patched = install(base);
  printf("BOOTSTRAP patched IAT slots=%d\n", patched);

  int64_t run_addr = get_export(base, "lp_payload_run");
  if (!run_addr) { printf("BOOTSTRAP ERROR no lp_payload_run export\n"); return 8; }
  payload_fn run = (payload_fn)(void *)(intptr_t)run_addr;
  char out[8192] = {0};
  run(out, (int)sizeof(out));

  /* The verdict is generic: check that the consumer's virtual-file read line
     carries the data we seeded, whatever that data was. This keeps the spike
     reusable for a second run with different content. */
  int sees = 0;
  {
    char needle[600];
    _snprintf_s(needle, sizeof(needle), _TRUNCATE, "data=\"%s\"", vdata);
    sees = strstr(out, needle) != NULL;
  }
  printf("BOOTSTRAP --- child consumer output ---\n%s", out);
  printf("BOOTSTRAP VERDICT=%s\n", sees ? "CHILD_SEES_VIRTUAL_FS" : "CHILD_DOES_NOT_SEE_VIRTUAL_FS");

  if (dm) dm((HINSTANCE)(intptr_t)base, DLL_PROCESS_DETACH, NULL);
  unmap_image(base);
  free(image);
  FreeLibrary(virt);

  /* The child does not need to delete payload.dll: zero-disk is M0's concern.
     This spike answers only whether a child process can be virtualized without
     remote injection, and whether AV accepts that pattern. */
  return sees ? 0 : 9;
}
