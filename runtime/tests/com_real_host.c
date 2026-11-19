/* L5.5 host: register a *real* in-proc COM server out of memory, let COM
 * activate it, then unregister it.
 *
 *   com_real_host.exe <dir-with-lpvirt.dll> <server.dll> <clsid> [--consume]
 *
 * Unlike tests\com_server.c this host does not own the component. The server is
 * a shipped Windows binary (wshom.ocx by default in the verify script) that was
 * written by someone else, has its own DllMain and CRT initialisation, and
 * registers itself by asking the system where it lives. Everything it needs
 * comes from the runtime:
 *
 *   - the image is read from disk once and served from the virtual filesystem
 *     under a path that does not exist (C:\virt\...)
 *   - DllRegisterServer's writes land in the in-memory hive, so no administrator
 *     is involved and HKCR is never touched
 *   - GetModuleFileNameW is answered with the virtual path, which is what the
 *     component then writes into InprocServer32
 *   - CoCreateInstance goes through combase, which reads the hive, asks
 *     LoadLibraryExW for the virtual path, and gets the image mapped by hand
 *
 * --consume deletes the server from disk after reading it, before it is mapped.
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
typedef int (*reg_stats_fn)(int32_t *, int);
typedef int (*api_hits_fn)(const char *);
typedef void (*api_reset_fn)(void);
typedef int (*log_count_fn)(void);
typedef int (*log_get_fn)(int, char *, int);
typedef int64_t (*map_fn)(const void *, int32_t);
typedef int32_t (*map_error_fn)(void);
typedef int64_t (*get_export_fn)(int64_t, const char *);
typedef int (*module_name_fn)(int64_t, wchar_t *, int);
typedef int (*set_path_fn)(int64_t, const wchar_t *);
typedef HRESULT(__stdcall *dll_reg_fn)(void);

#define GET(h, name, type) (type)(void *)GetProcAddress(h, name)

static void print_hits(api_hits_fn hits, const char *label) {
  static const char *apis[] = {
      "RegOpenKeyExW",   "RegOpenKeyExA",   "RegCreateKeyExW", "RegSetValueExW",
      "RegQueryValueExW", "RegGetValueW",   "RegEnumKeyExW",   "RegEnumValueW",
      "RegQueryInfoKeyW", "RegDeleteKeyW",  "RegDeleteValueW", "RegCloseKey",
      "NtOpenKey",       "NtQueryValueKey", "NtQueryKey",     "NtClose",
      "LoadLibraryExW",  "LoadLibraryW",    "GetProcAddress",  "GetModuleFileNameW",
      "CreateFileW",     "ReadFile"};
  printf("%s:", label);
  for (int i = 0; i < (int)(sizeof(apis) / sizeof(apis[0])); i++) {
    int n = hits(apis[i]);
    if (n > 0) printf(" %s=%d", apis[i], n);
  }
  printf("\n");
}

static void print_reg_stats(reg_stats_fn reg_stats, const char *label) {
  int32_t rs[8] = {0};
  int n = reg_stats(rs, 32);
  printf("%s: open=%ld create=%ld enum=%ld delete=%ld query=%ld write=%ld (n=%d)\n", label,
         (long)rs[0], (long)rs[1], (long)rs[2], (long)rs[3], (long)rs[4], (long)rs[5], n);
}

static void dump_log(log_count_fn count, log_get_fn get, const char *label) {
  int n = count();
  printf("%s: %d entries\n", label, n);
  int from = n > 20 ? n - 20 : 0;
  for (int i = from; i < n; i++) {
    char line[512] = {0};
    get(i, line, sizeof(line));
    printf("  [%d] %s\n", i, line);
  }
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc < 4) {
    printf("usage: com_real_host.exe <dir> <server.dll> <clsid> [--consume]\n");
    return 2;
  }
  const char *dir = argv[1];
  const char *server = argv[2];
  const char *clsid_text = argv[3];
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
  reg_stats_fn reg_stats = GET(virt, "lp_reg_stats", reg_stats_fn);
  api_hits_fn hits = GET(virt, "lp_api_hits", api_hits_fn);
  api_reset_fn hits_reset = GET(virt, "lp_api_hits_reset", api_reset_fn);
  log_count_fn log_count = GET(virt, "lp_reg_log_count", log_count_fn);
  log_get_fn log_get = GET(virt, "lp_reg_log_get", log_get_fn);
  map_fn map_image = GET(virt, "lp_map_image", map_fn);
  map_error_fn map_error = GET(virt, "lp_map_error", map_error_fn);
  get_export_fn get_export = GET(virt, "lp_get_export", get_export_fn);
  module_name_fn module_name = GET(virt, "lp_get_module_file_name_w", module_name_fn);
  set_path_fn set_path = GET(virt, "lp_set_module_path", set_path_fn);
  if (!init || !reset || !add_file || !install || !reg_stats || !hits || !hits_reset ||
      !log_count || !log_get || !map_image || !map_error || !get_export || !module_name ||
      !set_path) {
    printf("MISSING EXPORT in lpvirt.dll\n");
    return 1;
  }

  init();
  reset();

  /* The virtual path: same directory as the real file, but under C:\virt. */
  const char *base = server;
  for (const char *p = server; *p; p++) {
    if (*p == '\\' || *p == '/') base = p + 1;
  }
  wchar_t virt_server[MAX_PATH];
  _snwprintf_s(virt_server, MAX_PATH, _TRUNCATE, L"C:\\virt\\%hs", base);

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
  add_file(virt_server, image, (int)size);
  printf("server         : %s (%ld bytes)\n", server, size);
  printf("virtual path   : %ls\n", virt_server);
  if (consume) {
    printf("server file deleted before mapping: %s\n",
           DeleteFileA(server) ? "YES" : "NO");
  }

  /* Map it and let it register itself. */
  int64_t server_base = map_image(image, (int32_t)size);
  if (!server_base) {
    printf("MAP server FAILED reason=%ld\n", (long)map_error());
    return 1;
  }
  printf("server mapped  : 0x%016llx, %d IAT slots patched\n",
         (unsigned long long)server_base, install(server_base));

  /* The registration the component is about to write needs its own location, and
   * for a hand-mapped image the only source of that is the runtime: the loader
   * has never heard of this base. Telling the runtime where the image lives is
   * what makes GetModuleFileNameW answer with the virtual path, which the
   * component then writes into InprocServer32. */
  set_path(server_base, virt_server);
  wchar_t self_name[MAX_PATH] = {0};
  int name_len = module_name(server_base, self_name, MAX_PATH);
  printf("module name    : %ls (chars=%d)\n", self_name, name_len);
  printf("name is virtual: %s\n", name_len > 0 ? "YES" : "NO");

  dll_reg_fn reg = (dll_reg_fn)(void *)(intptr_t)get_export(server_base, "DllRegisterServer");
  dll_reg_fn unreg = (dll_reg_fn)(void *)(intptr_t)get_export(server_base, "DllUnregisterServer");
  if (!reg) {
    printf("MISSING DllRegisterServer export\n");
    return 1;
  }
  hits_reset();
  HRESULT hr_reg = reg();
  printf("DllRegisterServer: 0x%08lx\n", (unsigned long)hr_reg);
  print_reg_stats(reg_stats, "hive after register");
  printf("registration thunks: RegCreateKeyExW=%d RegSetValueExW=%d RegCloseKey=%d\n",
         hits("RegCreateKeyExW"), hits("RegSetValueExW"), hits("RegCloseKey"));
  print_hits(hits, "registration thunks (all)");
  if (hr_reg != S_OK) {
    dump_log(log_count, log_get, "registration requests");
    return 1;
  }

  /* Let the class database see the hive. */
  int patched = 0;
  const char *targets[] = {"combase.dll", "ole32.dll"};
  for (int i = 0; i < 2; i++) {
    HMODULE m = GetModuleHandleA(targets[i]);
    if (!m) continue;
    int n = install((int64_t)(intptr_t)m);
    printf("%s: %d slots patched\n", targets[i], n);
    if (n > 0) patched++;
  }
  if (patched == 0) {
    printf("NO COM MODULE PATCHED\n");
    return 1;
  }

  /* Activate. This host is an ordinary program in the same process; the load
   * that matters happens inside combase, whose IAT the runtime just rewrote. */
  CLSID clsid;
  wchar_t wide_clsid[64] = {0};
  MultiByteToWideChar(CP_ACP, 0, clsid_text, -1, wide_clsid, 64);
  HRESULT hr = CLSIDFromString(wide_clsid, &clsid);
  if (hr != S_OK) {
    printf("BAD CLSID %s (0x%08lx)\n", clsid_text, (unsigned long)hr);
    return 1;
  }
  HRESULT hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  printf("CoInitializeEx : 0x%08lx\n", (unsigned long)hr_init);

  hits_reset();
  IUnknown *obj = NULL;
  HRESULT hr_create = CoCreateInstance(&clsid, NULL, CLSCTX_INPROC_SERVER, &IID_IUnknown,
                                       (void **)&obj);
  printf("CoCreateInstance: 0x%08lx\n", (unsigned long)hr_create);
  printf("object         : %s\n", obj ? "created" : "none");
  if (obj) {
    ULONG refs = obj->lpVtbl->Release(obj);
    printf("released       : refs=%lu\n", (unsigned long)refs);
  }
  printf("activation thunks: LoadLibraryExW=%d LoadLibraryW=%d GetProcAddress=%d "
         "GetModuleFileNameW=%d RegGetValueW=%d\n",
         hits("LoadLibraryExW"), hits("LoadLibraryW"), hits("GetProcAddress"),
         hits("GetModuleFileNameW"), hits("RegGetValueW"));
  print_reg_stats(reg_stats, "hive after activate");
  dump_log(log_count, log_get, "activation requests");

  if (unreg) {
    printf("DllUnregisterServer: 0x%08lx\n", (unsigned long)unreg());
    print_reg_stats(reg_stats, "hive after unregister");
  }
  if (hr_init == S_OK || hr_init == S_FALSE) CoUninitialize();
  return (hr_create == S_OK && obj != NULL) ? 0 : 1;
}
