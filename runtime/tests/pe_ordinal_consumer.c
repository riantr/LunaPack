/* L3.1 fixture: a no-CRT EXE that imports pe_add BY ORDINAL from pe_provider.
 *
 * The import library is built from pe_ordinal_consumer.def with NONAME, so the
 * linker emits an ordinal thunk (high bit set, low word = ordinal 1) in this
 * image's IAT. When the launcher maps this image, the mapper must resolve that
 * ordinal against pe_provider's export table (L3.1). Before L3.1 the mapper
 * returned MAP_ORDINAL_IMPORT and refused the image.
 */
#include <windows.h>

/* Provided by the NONAME import library -> ordinal 1 of pe_provider.dll. */
int ordinal_add(int a, int b);

static int nlen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void puts_nocr(const char *s) {
  DWORD n = 0;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, (DWORD)nlen(s), &n, NULL);
}

int pe_ordinal_main(void) {
  int r = ordinal_add(40, 2);
  puts_nocr(r == 42 ? "ORDINAL IMPORT OK\n" : "ORDINAL IMPORT FAIL\n");
  return r == 42 ? 0 : 1;
}
