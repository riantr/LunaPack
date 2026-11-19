/* L5 host: register a component into the in-memory hive, then let real COM
 * activate it out of the virtual filesystem.
 *
 *   com_host.exe <dir-with-lpvirt.dll> <com_server.dll> <com_consumer.exe> [--consume]
 *
 * Steps, in the order the checks care about:
 *   1. the server image is read into the virtual filesystem at C:\virt
 *   2. the image is mapped by hand and its DllRegisterServer is called, so the
 *      registration writes go through the runtime's registry thunks
 *   3. the IATs of combase and ole32 are rewritten, which is what makes the
 *      class database read the hive instead of the real registry
 *   4. the consumer is mapped and run; its CoCreateInstance is served by
 *      combase, which finds InprocServer32 in the hive and asks LoadLibrary for
 *      a path that exists only in memory
 *   5. DllUnregisterServer removes the class again, leaving the hive clean
 *
 * --consume deletes the server file from disk before it is ever mapped, so a
 * passing run means nothing was loaded from the filesystem.
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
typedef int (*stats_fn)(int32_t *, int);
typedef int (*reg_stats_fn)(int32_t *, int);
typedef int (*api_hits_fn)(const char *);
typedef void (*api_reset_fn)(void);
typedef int (*log_count_fn)(void);
typedef int (*log_get_fn)(int, char *, int);
typedef int64_t (*map_fn)(const void *, int32_t);
typedef int32_t (*map_error_fn)(void);
typedef int64_t (*get_entry_fn)(int64_t);
typedef int64_t (*get_export_fn)(int64_t, const char *);
typedef int (*entry_fn)(void);
typedef int (*dllmain_fn)(void *, unsigned long, void *);
typedef int (*set_path_fn)(int64_t, const wchar_t *);
typedef int (*note_base_fn)(int64_t);
typedef HRESULT(__stdcall *dll_reg_fn)(void);

#define GET(h, name, type) (type)(void *)GetProcAddress(h, name)

static void dump_log(log_count_fn count, log_get_fn get, const char *label) {
  int n = count();
  printf("%s: %d entries\n", label, n);
  int from = n > 24 ? n - 24 : 0;
  for (int i = from; i < n; i++) {
    char line[512] = {0};
    get(i, line, sizeof(line));
    printf("  [%d] %s\n", i, line);
  }
}

static void print_reg_stats(reg_stats_fn reg_stats, const char *label) {
  int32_t rs[8] = {0};
  int n = reg_stats(rs, 32);
  printf("%s: open=%ld create=%ld enum=%ld delete=%ld query=%ld write=%ld (n=%d)\n", label,
         (long)rs[0], (long)rs[1], (long)rs[2], (long)rs[3], (long)rs[4], (long)rs[5], n);
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc < 4) {
    printf("usage: com_host.exe <dir> <com_server.dll> <com_consumer.exe> [--consume]\n");
    return 2;
  }
  const char *dir = argv[1];
  const char *server = argv[2];
  const char *consumer = argv[3];
  int consume = 0;
  for (int i = 4; i < argc; i++) {
    if (strcmp(argv[i], "--consume") == 0) consume = 1;
  }

  char virt_path[MAX_PATH];
  _snprintf_s(virt_path, sizeof(virt_path), _TRUNCATE, "%s\\lpvirt.dll", dir);
  HMODULE virt = LoadLibraryA(virt_path);
  if (!virt) {
    printf("LOAD lpvirt FAILED gle=%lu (%s)\n", GetLastError(), virt_path);
    return 1;
  }

  init_fn init = GET(virt, "moonbit_init", init_fn);
  reset_fn reset = GET(virt, "lp_virt_reset", reset_fn);
  add_file_fn add_file = GET(virt, "lp_virt_add_file", add_file_fn);
  install_fn install = GET(virt, "lp_install_iat_hooks", install_fn);
  stats_fn stats = GET(virt, "lp_virt_stats", stats_fn);
  reg_stats_fn reg_stats = GET(virt, "lp_reg_stats", reg_stats_fn);
  api_hits_fn hits = GET(virt, "lp_api_hits", api_hits_fn);
  api_reset_fn hits_reset = GET(virt, "lp_api_hits_reset", api_reset_fn);
  log_count_fn log_count = GET(virt, "lp_reg_log_count", log_count_fn);
  log_get_fn log_get = GET(virt, "lp_reg_log_get", log_get_fn);
  map_fn map_image = GET(virt, "lp_map_image", map_fn);
  map_error_fn map_error = GET(virt, "lp_map_error", map_error_fn);
  get_entry_fn get_entry = GET(virt, "lp_get_entry", get_entry_fn);
  get_export_fn get_export = GET(virt, "lp_get_export", get_export_fn);
  set_path_fn set_path = GET(virt, "lp_set_module_path", set_path_fn);
  note_base_fn note_attach = GET(virt, "lp_mapped_attach", note_base_fn);
  if (!init || !reset || !add_file || !install || !stats || !reg_stats || !hits ||
      !hits_reset || !log_count || !log_get || !map_image || !map_error || !get_entry ||
      !get_export || !set_path || !note_attach) {
    printf("MISSING EXPORT in lpvirt.dll\n");
    return 1;
  }

  init();
  reset();

  /* 1. the server image goes into the virtual filesystem */
  FILE *f = fopen(server, "rb");
  if (!f) {
    printf("READ server FAILED (%s)\n", server);
    return 1;
  }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char *image = (unsigned char *)malloc((size_t)size);
  if (!image || fread(image, 1, (size_t)size, f) != (size_t)size) {
    printf("READ server FAILED (short read)\n");
    fclose(f);
    return 1;
  }
  fclose(f);
  /* The component lives at a path that does not exist on disk. It is named after
   * the file it was read from, so the same host can drive the no-CRT build and
   * the ordinary build. */
  const char *base_name = server;
  for (const char *p = server; *p; p++) {
    if (*p == '\\' || *p == '/') base_name = p + 1;
  }
  wchar_t virt_server[MAX_PATH];
  _snwprintf_s(virt_server, MAX_PATH, _TRUNCATE, L"C:\\virt\\%hs", base_name);
  add_file(virt_server, image, (int)size);
  printf("server in virtual filesystem: %ld bytes at %ls\n", size, virt_server);
  if (consume) {
    if (DeleteFileA(server)) {
      printf("server file deleted before mapping: YES\n");
    } else {
      printf("server file deleted before mapping: NO (gle=%lu)\n", GetLastError());
    }
  }

  /* 2. register through the hive */
  int64_t server_base = map_image(image, (int32_t)size);
  if (!server_base) {
    printf("MAP server FAILED reason=%ld\n", (long)map_error());
    return 1;
  }
  int server_slots = install(server_base);
  printf("server mapped at 0x%016llx, %d IAT slots patched\n",
         (unsigned long long)server_base, server_slots);
  /* Tell the runtime where this image lives, then run its entry point: a
   * manually mapped module gets no DllMain from the loader, and an ordinary
   * component initialises itself (and learns its own path) there. */
  set_path(server_base, virt_server);
  int64_t entry = get_entry(server_base);
  dllmain_fn dll_main = (dllmain_fn)(void *)(intptr_t)entry;
  int attached = entry ? dll_main((void *)(intptr_t)server_base, 1, NULL) : -1;
  if (entry) note_attach(server_base);
  printf("DllMain(DLL_PROCESS_ATTACH): %s\n",
         entry ? (attached ? "TRUE" : "FALSE") : "no entry point");
  dll_reg_fn reg = (dll_reg_fn)(void *)(intptr_t)get_export(server_base, "DllRegisterServer");
  dll_reg_fn unreg = (dll_reg_fn)(void *)(intptr_t)get_export(server_base, "DllUnregisterServer");
  if (!reg || !unreg) {
    printf("MISSING DllRegisterServer/DllUnregisterServer export\n");
    return 1;
  }
  hits_reset();
  HRESULT hr_reg = reg();
  printf("DllRegisterServer returned 0x%08lx\n", (unsigned long)hr_reg);
  printf("register thunks: RegCreateKeyExW=%d RegSetValueExW=%d RegCloseKey=%d RegDeleteKeyW=%d\n",
         hits("RegCreateKeyExW"), hits("RegSetValueExW"), hits("RegCloseKey"),
         hits("RegDeleteKeyW"));
  print_reg_stats(reg_stats, "hive after register");
  dump_log(log_count, log_get, "registration requests");

  /* 3. let the class database see the hive */
  int patched_modules = 0, patched_slots = 0;
  const char *targets[] = {"combase.dll", "ole32.dll"};
  for (int i = 0; i < 2; i++) {
    HMODULE m = GetModuleHandleA(targets[i]);
    if (!m) continue;
    int n = install((int64_t)(intptr_t)m);
    printf("%s: %d slots patched\n", targets[i], n);
    if (n > 0) {
      patched_modules++;
      patched_slots += n;
    }
  }
  if (patched_modules == 0) {
    printf("NO COM MODULE PATCHED\n");
    return 1;
  }

  /* 4. activate */
  f = fopen(consumer, "rb");
  if (!f) {
    printf("READ consumer FAILED (%s)\n", consumer);
    return 1;
  }
  fseek(f, 0, SEEK_END);
  long csize = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char *cimage = (unsigned char *)malloc((size_t)csize);
  if (!cimage || fread(cimage, 1, (size_t)csize, f) != (size_t)csize) {
    printf("READ consumer FAILED (short read)\n");
    fclose(f);
    return 1;
  }
  fclose(f);
  int64_t base = map_image(cimage, (int32_t)csize);
  if (!base) {
    printf("MAP consumer FAILED reason=%ld\n", (long)map_error());
    return 1;
  }
  int slots = install(base);
  printf("consumer mapped, %d IAT slots patched\n", slots);
  hits_reset();
  int64_t client_entry = get_entry(base);
  entry_fn run = (entry_fn)(void *)(intptr_t)client_entry;
  int rc = run();
  printf("consumer exit=%d\n", rc);

  static const char *apis[] = {
      "RegOpenKeyExW",     "RegOpenKeyExA",       "RegGetValueW",
      "RegQueryValueExW",  "NtOpenKey",           "NtQueryValueKey",
      "RegCloseKey",       "RegEnumKeyExW",       "RegEnumValueW",
      "RegQueryInfoKeyW",  "RegCreateKeyExW",     "RegDeleteKeyW",
      "LoadLibraryExW",    "LoadLibraryW",        "GetProcAddress",
      "GetModuleFileNameW", "CreateFileW",        "ReadFile"};
  printf("thunks used:");
  for (int i = 0; i < (int)(sizeof(apis) / sizeof(apis[0])); i++) {
    int n = hits(apis[i]);
    if (n > 0) printf(" %s=%d", apis[i], n);
  }
  printf("\n");
  print_reg_stats(reg_stats, "hive after activate");
  dump_log(log_count, log_get, "registry requests");

  /* 5. unregister */
  HRESULT hr_unreg = unreg();
  printf("DllUnregisterServer returned 0x%08lx\n", (unsigned long)hr_unreg);
  print_reg_stats(reg_stats, "hive after unregister");

  int32_t s[16] = {0};
  stats(s, 64);
  printf("counters: creates=%ld reads=%ld fallthroughs=%ld regq=%ld patched=%ld\n",
         (long)s[0], (long)s[1], (long)s[2], (long)s[3], (long)s[4]);
  return rc == 0 ? 0 : 1;
}
