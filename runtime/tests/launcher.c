/* Thin launcher spike (L2.0) + ExitProcess strategy (L2.1).
 *
   launcher.exe <dir-with-lpvirt.dll> <target.exe> [--consume] [--thread]
 *
   --thread runs the mapped entry point on a worker thread. A CRT target calls
   ExitProcess at the end of main(); the runtime redirects that to ExitThread,
   which ends only the worker. The launcher then reads the target's real exit
   code via lp_virt_exit_query and continues to its epilogue. Without --thread
   the entry is called directly (fine for a no-CRT /ENTRY target).

   The launcher loads lpvirt.dll into its OWN process, seeds a small virtual
   filesystem, reads the target EXE into a byte array, maps that array with
   lp_map_image, installs the IAT hooks on the mapped image, and calls its
   AddressOfEntryPoint directly. No LoadLibrary on the target, no remote
   injection, and - with --consume - the target file is deleted before it is
   mapped. This is the execution carrier that L1/L2 Tier B checks need; it is
   deliberately not a product launcher (no archive format, no CLI yet).
 *
   The target must be a PE32+ EXE built with a no-CRT /ENTRY entry point (see
   mini_exe.c). A CRT entry point would call ExitProcess and kill the launcher;
   CRT compatibility belongs to L3.
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
typedef int64_t (*map_fn)(const void *, int32_t);
typedef int32_t (*map_error_fn)(void);
typedef int64_t (*get_entry_fn)(int64_t);
typedef int32_t (*unmap_fn)(int64_t);
typedef int (*entry_fn)(void);
typedef int (*exit_query_fn)(int64_t);
typedef int (*set_temp_fn)(int64_t);
typedef int (*lifecycle_stats_fn)(int32_t *, int);

#define GET(h, name, type) (type)(void *)GetProcAddress(h, name)

/* Context passed to the worker thread. */
typedef struct {
  entry_fn entry;
  int rc;
} ThreadCtx;

static DWORD WINAPI run_entry_thread(LPVOID p) {
  ThreadCtx *c = (ThreadCtx *)p;
  c->rc = c->entry();
  return (DWORD)c->rc;
}

static void join(char *out, size_t cap, const char *dir, const char *name) {
  _snprintf_s(out, cap, _TRUNCATE, "%s\\%s", dir, name);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    printf("usage: launcher.exe <dir> <target.exe> [--consume] [--thread]\n");
    return 2;
  }
  const char *dir = argv[1];
  const char *target = argv[2];
  int consume = 0, use_thread = 0;
  for (int i = 3; i < argc; i++) {
    if (strcmp(argv[i], "--consume") == 0) consume = 1;
    if (strcmp(argv[i], "--thread") == 0) use_thread = 1;
  }

  char virt_path[MAX_PATH];
  join(virt_path, sizeof(virt_path), dir, "lpvirt.dll");
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
  map_fn map_image = GET(virt, "lp_map_image", map_fn);
  map_error_fn map_error = GET(virt, "lp_map_error", map_error_fn);
  get_entry_fn get_entry = GET(virt, "lp_get_entry", get_entry_fn);
  unmap_fn unmap_image = GET(virt, "lp_unmap_image", unmap_fn);
  exit_query_fn exit_query = GET(virt, "lp_virt_exit_query", exit_query_fn);
  set_temp_fn set_temp = GET(virt, "lp_virt_set_temp_path", set_temp_fn);
  lifecycle_stats_fn lifecycle = GET(virt, "lp_virt_lifecycle_stats", lifecycle_stats_fn);
  if (!init || !reset || !add_file || !install || !stats || !map_image ||
      !map_error || !get_entry || !unmap_image || !exit_query || !set_temp ||
      !lifecycle) {
    printf("MISSING EXPORT in lpvirt.dll\n");
    return 1;
  }

  init();
  reset();
  /* Spike seed: in L6 this comes from the signed virtual archive. */
  add_file(L"C:\\virt\\hello.txt", "VIRTUAL-FS-OK", 13);
  add_file(L"C:\\virt\\ansi.txt", "ANSI", 4);
  add_file(L"C:\\cfg\\seed.txt", "SEED", 4);
  set_temp(L"C:\\virt\\tmp");
  printf("seeded virtual files: 3 + temp path\n");

  FILE *tf = fopen(target, "rb");
  if (!tf) {
    printf("READ target FAILED (%s)\n", target);
    return 1;
  }
  fseek(tf, 0, SEEK_END);
  long size = ftell(tf);
  fseek(tf, 0, SEEK_SET);
  unsigned char *image = (unsigned char *)malloc((size_t)size);
  if (!image || fread(image, 1, (size_t)size, tf) != (size_t)size) {
    printf("READ target FAILED (short read)\n");
    fclose(tf);
    return 1;
  }
  fclose(tf);
  printf("target image read into memory: %ld bytes\n", size);

  if (consume) {
    if (DeleteFileA(target)) {
      printf("target file deleted before mapping: YES\n");
    } else {
      printf("target file deleted before mapping: NO (gle=%lu)\n", GetLastError());
    }
  }

  int64_t base = map_image(image, (int32_t)size);
  if (!base) {
    printf("MANUAL MAP FAILED reason=%ld\n", (long)map_error());
    free(image);
    return 1;
  }
  printf("mapped image base          : 0x%016llx\n", (unsigned long long)base);
  printf("OS loader knows target     : %s\n",
         GetModuleHandleA(target) ? "YES (unexpected)" : "NO (expected)");
  printf("target file still on disk  : %s\n",
         GetFileAttributesA(target) == INVALID_FILE_ATTRIBUTES ? "NO" : "YES");

  int patched = install(base);
  printf("patched IAT slots          : %d\n", patched);
  if (patched <= 0) {
    printf("HOOK INSTALL FAILED\n");
    return 1;
  }

  int64_t entry = get_entry(base);
  if (!entry) {
    printf("NO ENTRY POINT\n");
    return 1;
  }
  printf("entry point                : 0x%016llx\n", (unsigned long long)entry);
  printf("worker thread              : %s\n", use_thread ? "YES" : "NO");
  fflush(stdout);
  entry_fn run = (entry_fn)(void *)(intptr_t)entry;
  int rc = 0;
  if (use_thread) {
    ThreadCtx ctx = {run, 0};
    HANDLE th = CreateThread(NULL, 0, run_entry_thread, &ctx, 0, NULL);
    if (!th) { printf("CreateThread FAILED gle=%lu\n", GetLastError()); return 1; }
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    rc = ctx.rc;
  } else {
    rc = run();
  }
  int exit_called = exit_query(NULL);
  int32_t target_code = 0;
  exit_query((int64_t)(intptr_t)&target_code);
  printf("mapped EXE exit code       : %d\n", rc);
  printf("ExitProcess intercepted    : %s (code=%d)\n",
         exit_called ? "YES" : "NO", (int)target_code);

  int32_t s[16] = {0};
  stats(s, 64);
  printf("counters: creates=%ld reads=%ld fallthroughs=%ld regq=%ld patched=%ld "
         "dyn=%ld writes=%ld seeks=%ld deletes=%ld renames=%ld infos=%ld "
         "comps=%ld ntdll=%ld\n",
         (long)s[0], (long)s[1], (long)s[2], (long)s[3], (long)s[4],
         (long)s[5], (long)s[6], (long)s[7], (long)s[8], (long)s[9],
         (long)s[10], (long)s[11], (long)s[12]);

  /* L2.4: the mapped EXE path plus any runtime LoadLibrary both went through
     the single installer. Layout: mapped,loaded,att,det,viol. */
  int32_t life[5] = {0};
  lifecycle(life, 20);
  printf("hook lifecycle: mapped=%ld loaded=%ld attach=%ld detach=%ld violations=%ld\n",
         (long)life[0], (long)life[1], (long)life[2], (long)life[3], (long)life[4]);

  unmap_image(base);
  free(image);
  FreeLibrary(virt);
  printf("%s\n", rc == 0 ? "THIN LAUNCHER OK" : "THIN LAUNCHER EXE FAILED");
  return rc == 0 ? 0 : 1;
}
