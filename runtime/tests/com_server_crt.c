/* L5.5: the same component built the ordinary way - with the C runtime, a
 * normal DllMain and no /NOENTRY - so that "a real component registers and is
 * activated out of the archive" is tested against a binary that looks like
 * every other in-proc server.
 *
 * The difference from com_server.dll is not cosmetic. This build lets the CRT
 * start-up run (our entry-point call has to reach _DllMainCRTStartup, not a
 * hand-written DllMain), and it registers itself through GetModuleFileNameW
 * instead of a hard-coded path, which is what a shipped server does.
 *
 * The source is shared: LP_CRT switches on both behaviours.
 */
#define LP_CRT 1
#include "com_server.c"
