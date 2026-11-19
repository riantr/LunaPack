/* L3.2 fixture: map pe_provider.dll and resolve exports from the mapped image.
 *
 * Verifies two things through the C ABI:
 *   - lp_get_export(base, "pe_forward") resolves the FORWARDED export to the
 *     real kernel32.GetCurrentProcessId address (non-zero, inside kernel32).
 *   - lp_get_export(base, "pe_add") resolves the normal export to an address
 *     inside the mapped image.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef void (*init_fn)(void);

typedef int64_t (*map_fn)(const void *, int32_t);
typedef int32_t (*map_error_fn)(void);
typedef int64_t (*get_export_fn)(int64_t, const char *);
typedef int32_t (*unmap_fn)(int64_t);
#define GET(h, name, type) (type)(void *)GetProcAddress(h, name)

int main(int argc, char **argv) {
  if (argc < 3) { printf("usage: pe_export_probe.exe <dir> <pe_provider.dll>\n"); return 2; }
  char virt[MAX_PATH], target[MAX_PATH];
  _snprintf_s(virt, sizeof(virt), _TRUNCATE, "%s\\lpvirt.dll", argv[1]);
  _snprintf_s(target, sizeof(target), _TRUNCATE, "%s", argv[2]);
  HMODULE v = LoadLibraryA(virt);
  if (!v) { printf("LOAD lpvirt FAILED\n"); return 1; }
  map_fn map_image = GET(v, "lp_map_image", map_fn);
  map_error_fn map_error = GET(v, "lp_map_error", map_error_fn);
  get_export_fn get_export = GET(v, "lp_get_export", get_export_fn);
  unmap_fn unmap = GET(v, "lp_unmap_image", unmap_fn);
  init_fn init = GET(v, "moonbit_init", init_fn);
  if (!map_image || !get_export || !unmap || !init) { printf("MISSING EXPORT\n"); return 1; }
  init();

  FILE *f = fopen(target, "rb");
  if (!f) { printf("READ provider FAILED\n"); return 1; }
  fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  unsigned char *img = (unsigned char *)malloc((size_t)sz);
  if (fread(img, 1, (size_t)sz, f) != (size_t)sz) { printf("SHORT READ\n"); return 1; }
  fclose(f);

  int64_t base = map_image(img, (int32_t)sz);
  if (!base) { printf("MAP FAILED reason=%ld\n", (long)map_error()); return 1; }
  printf("mapped provider base: 0x%016llx\n", (unsigned long long)base);

  int64_t pe_add = get_export(base, "pe_add");
  int64_t pe_forward = get_export(base, "pe_forward");
  printf("pe_add     = 0x%016llx (in mapped image: %s)\n",
         (unsigned long long)pe_add, (pe_add >= base) ? "YES" : "NO");
  printf("pe_forward = 0x%016llx (resolved: %s)\n",
         (unsigned long long)pe_forward, pe_forward != 0 ? "YES" : "NO");

  /* kernel32.GetCurrentProcessId real address, for comparison. */
  HMODULE k32 = GetModuleHandleA("kernel32.dll");
  void *real = (void *)GetProcAddress(k32, "GetCurrentProcessId");
  printf("forwarded matches kernel32: %s\n",
         pe_forward == (int64_t)(intptr_t)real ? "YES" : "NO");

  unmap(base);
  free(img);
  FreeLibrary(v);
  int ok = pe_add >= base && pe_forward != 0 && pe_forward == (int64_t)(intptr_t)real;
  printf("%s\n", ok ? "PE EXPORT PROBE OK" : "PE EXPORT PROBE FAIL");
  return ok ? 0 : 1;
}
