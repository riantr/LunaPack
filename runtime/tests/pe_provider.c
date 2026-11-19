/* L3 fixture: a provider DLL that exports:
 *   - pe_add         (name + ordinal 1)
 *   - pe_forward     (name + ordinal 2) -> forwarded to kernel32.GetCurrentProcessId
 * The .def file makes the forwarding explicit. Used to test the mapper's
 * ordinal-import resolution (L3.1) and forwarded-export resolution (L3.2).
 */
#include <windows.h>

__declspec(dllexport) int pe_add(int a, int b) { return a + b; }

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved) {
  (void)h; (void)reason; (void)reserved;
  return TRUE;
}
