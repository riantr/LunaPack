/* End-to-end harness for the in-process runtime.

   It loads the MoonBit DLL into its OWN process, seeds a memory filesystem
   and registry hive, reads the consumer DLL into a byte array, and maps that
   array with lp_map_image. No LoadLibrary is ever called on the consumer, so
   the consumer does not have to exist as a file while it runs. With the
   --consume argument the harness even deletes the file after reading it.

   Usage: host.exe <directory-with-lpvirt.dll-and-payload.dll> [--consume]
*/
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef void (*init_fn)(void);
typedef void (*reset_fn)(void);
typedef int (*add_file_fn)(const wchar_t *, const void *, int);
typedef int (*set_reg_fn)(int64_t, const wchar_t *, const wchar_t *, int,
                          const void *, int);
typedef int (*install_fn)(int64_t);
typedef int (*stats_fn)(int32_t *, int);
typedef int64_t (*map_fn)(const void *, int32_t);
typedef int32_t (*map_error_fn)(void);
typedef int64_t (*get_export_fn)(int64_t, const char *);
typedef int64_t (*get_entry_fn)(int64_t);
typedef int32_t (*unmap_fn)(int64_t);
typedef int (*payload_fn)(char *, int);
typedef BOOL (WINAPI *dll_main_fn)(HINSTANCE, DWORD, LPVOID);

#define GET(h, name, type) (type)(void *)GetProcAddress(h, name)

static void join(char *out, size_t cap, const char *dir, const char *name) {
  _snprintf_s(out, cap, _TRUNCATE, "%s\\%s", dir, name);
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : ".";
  int consume = argc > 2 && strcmp(argv[2], "--consume") == 0;
  char virt_path[MAX_PATH], payload_path[MAX_PATH], real_path[MAX_PATH];
  join(virt_path, sizeof(virt_path), dir, "lpvirt.dll");
  join(payload_path, sizeof(payload_path), dir, "payload.dll");
  join(real_path, sizeof(real_path), dir, "real.txt");

  HMODULE virt = LoadLibraryA(virt_path);
  if (!virt) {
    printf("LOAD lpvirt FAILED gle=%lu (%s)\n", GetLastError(), virt_path);
    return 1;
  }
  init_fn init = GET(virt, "moonbit_init", init_fn);
  reset_fn reset = GET(virt, "lp_virt_reset", reset_fn);
  add_file_fn add_file = GET(virt, "lp_virt_add_file", add_file_fn);
  set_reg_fn set_reg = GET(virt, "lp_virt_set_reg", set_reg_fn);
  install_fn install = GET(virt, "lp_install_iat_hooks", install_fn);
  stats_fn stats = GET(virt, "lp_virt_stats", stats_fn);
  map_fn map_image = GET(virt, "lp_map_image", map_fn);
  map_error_fn map_error = GET(virt, "lp_map_error", map_error_fn);
  get_export_fn get_export = GET(virt, "lp_get_export", get_export_fn);
  get_entry_fn get_entry = GET(virt, "lp_get_entry", get_entry_fn);
  unmap_fn unmap_image = GET(virt, "lp_unmap_image", unmap_fn);
  if (!init || !reset || !add_file || !set_reg || !install || !stats ||
      !map_image || !map_error || !get_export || !get_entry || !unmap_image) {
    printf("MISSING EXPORT in lpvirt.dll\n");
    return 1;
  }

  /* The MoonBit runtime inside the DLL must be initialized before any
     allocation takes place. */
  init();
  reset();

  const char *hello = "VIRTUAL-FS-OK";
  add_file(L"C:\\virt\\hello.txt", hello, (int)strlen(hello));
  add_file(L"C:\\virt\\note.txt", "NOTE", 4);
  const char *dyn_data = "DYNAMIC-HOOK-OK";
  add_file(L"C:\\virt\\dynamic.txt", dyn_data, (int)strlen(dyn_data));

  WCHAR product[] = L"LunaPack Virtual FS";
  int seeded = set_reg((int64_t)(intptr_t)HKEY_LOCAL_MACHINE,
                       L"SOFTWARE\\LunaPack", L"Product", REG_SZ,
                       product, (int)((wcslen(product) + 1) * sizeof(WCHAR)));
  printf("seeded virtual HKLM value: %s\n", seeded == 0 ? "OK" : "FAILED");

  /* A real file, to prove that non-virtual requests fall through. */
  FILE *f = fopen(real_path, "wb");
  if (f) { fwrite("REAL-FS-OK", 1, 10, f); fclose(f); }
  SetEnvironmentVariableA("LUNAPACK_REAL_FILE", real_path);

  /* Read the consumer image once. In a real bundle these bytes come from the
     decrypted archive in memory, not from a file. */
  FILE *pf = fopen(payload_path, "rb");
  if (!pf) { printf("READ payload FAILED (%s)\n", payload_path); return 1; }
  fseek(pf, 0, SEEK_END);
  long size = ftell(pf);
  fseek(pf, 0, SEEK_SET);
  unsigned char *image = (unsigned char *)malloc((size_t)size);
  if (!image || fread(image, 1, (size_t)size, pf) != (size_t)size) {
    printf("READ payload FAILED (short read)\n");
    fclose(pf);
    return 1;
  }
  fclose(pf);
  printf("payload image read into memory: %ld bytes\n", size);

  if (consume) {
    /* Stronger proof: the file is gone before the image is mapped. */
    if (DeleteFileA(payload_path)) {
      printf("payload file deleted before mapping: YES\n");
    } else {
      printf("payload file deleted before mapping: NO (gle=%lu)\n", GetLastError());
    }
  }

  int64_t base = map_image(image, (int32_t)size);
  if (!base) {
    printf("MANUAL MAP FAILED reason=%ld\n", (long)map_error());
    free(image);
    return 1;
  }
  printf("mapped image base          : 0x%016llx\n", (unsigned long long)base);
  printf("OS loader knows payload.dll: %s\n",
         GetModuleHandleW(L"payload.dll") ? "YES (unexpected)" : "NO (expected)");
  printf("payload file still on disk : %s\n",
         GetFileAttributesA(payload_path) == INVALID_FILE_ATTRIBUTES ? "NO" : "YES");

  /* The OS loader is not involved, so the host runs DllMain itself. */
  int64_t entry = get_entry(base);
  dll_main_fn dm = NULL;
  int dllmain_ok = -1;
  if (entry) {
    dm = (dll_main_fn)(void *)(intptr_t)entry;
    dllmain_ok = dm((HINSTANCE)(intptr_t)base, DLL_PROCESS_ATTACH, NULL) ? 1 : 0;
  }
  printf("DllMain(DLL_PROCESS_ATTACH): %s\n",
         dllmain_ok == 1 ? "TRUE" : (dllmain_ok == 0 ? "FALSE" : "skipped"));

  int patched = install(base);
  printf("patched IAT slots          : %d (expected 12)\n", patched);
  if (patched <= 0) { printf("HOOK INSTALL FAILED\n"); return 1; }

  int64_t run_addr = get_export(base, "lp_payload_run");
  if (!run_addr) { printf("EXPORT lp_payload_run NOT FOUND\n"); return 1; }
  payload_fn run = (payload_fn)(void *)(intptr_t)run_addr;
  char out[4096] = {0};
  run(out, (int)sizeof(out));
  printf("--- consumer output ---\n%s------------------------\n", out);

  int32_t s[6] = {0};
  stats(s, 24);
  printf("counters: virtual_creates=%ld virtual_reads=%ld fallthroughs=%ld "
         "reg_queries=%ld patched=%ld dynamic_hits=%ld\n",
         (long)s[0], (long)s[1], (long)s[2], (long)s[3], (long)s[4],
         (long)s[5]);

  /* Prove the HKLM write never touched the real registry. The host's own
     advapi32 calls are NOT hooked. */
  HKEY k = NULL;
  LONG st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\LunaPack", 0,
                          KEY_READ, &k);
  if (st == ERROR_SUCCESS) {
    DWORD t = 0, v = 0, sz = sizeof(v);
    LONG q = RegQueryValueExW(k, L"Version", NULL, &t, (LPBYTE)&v, &sz);
    printf("real registry Version query = %ld (2 means never written)\n",
           (long)q);
    RegCloseKey(k);
  } else {
    printf("real registry key open = %ld (2 means key never created)\n",
           (long)st);
  }

  /* The CRT of the payload registered onexit handlers while it was attached.
     Detach first, so process shutdown does not walk code in an image we are
     about to release. */
  if (dm) {
    dm((HINSTANCE)(intptr_t)base, DLL_PROCESS_DETACH, NULL);
    printf("DllMain(DLL_PROCESS_DETACH): done\n");
  }
  unmap_image(base);
  free(image);
  FreeLibrary(virt);
  return 0;
}
