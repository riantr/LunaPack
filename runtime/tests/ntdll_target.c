/* L2.3 spike target: bypass the Win32 IAT layer and call the native file API.
 *
 * The thin launcher maps this PE into its own process and installs the usual
 * Win32 IAT hooks. This target does NOT call CreateFileW/ReadFile directly.
 * Instead it resolves NtCreateFile/NtOpenFile/NtReadFile/NtClose through
 * GetProcAddress (itself a hooked slot) and calls the native entry points.
 *
 * A real NtCreateFile on C:\virt\hello.txt must fail (nothing on disk). If the
 * read succeeds, the ntdll-boundary thunk served it from the in-memory VFS.
 * The second half opens a real file through the same native API, proving the
 * fall-through to the unmodified OS still works.
 *
 * Linked with /ENTRY:ntdll_main /NODEFAULTLIB: no CRT, no ExitProcess.
 */
#include <windows.h>

#define NTAPI __stdcall
#define FILE_OPEN 1
#define FILE_NON_DIRECTORY_FILE 0x00000040

typedef struct {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct {
  ULONG Length;
  PVOID RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct {
  PVOID Pointer;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI *NtCreateFileFn)(PHANDLE, ACCESS_MASK,
                                        POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                        PLARGE_INTEGER, ULONG, ULONG, ULONG,
                                        ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI *NtOpenFileFn)(PHANDLE, ACCESS_MASK,
                                      POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                      ULONG, ULONG);
typedef NTSTATUS(NTAPI *NtReadFileFn)(HANDLE, HANDLE, PVOID, PVOID,
                                      PIO_STATUS_BLOCK, PVOID, ULONG,
                                      PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI *NtCloseFn)(HANDLE);

static void put(HANDLE h, const char *s, int n) {
  DWORD wrote = 0;
  WriteFile(h, s, (DWORD)n, &wrote, NULL);
}

static int wide_len(const WCHAR *s) {
  int n = 0;
  while (s[n] != 0) n++;
  return n;
}

static void init_us(PUNICODE_STRING us, PWSTR buf) {
  us->Length = (USHORT)(wide_len(buf) * sizeof(WCHAR));
  us->MaximumLength = (USHORT)(us->Length + sizeof(WCHAR));
  us->Buffer = buf;
}

static void init_oa(POBJECT_ATTRIBUTES oa, PUNICODE_STRING name) {
  oa->Length = sizeof(OBJECT_ATTRIBUTES);
  oa->RootDirectory = NULL;
  oa->ObjectName = name;
  oa->Attributes = 0;
  oa->SecurityDescriptor = NULL;
  oa->SecurityQualityOfService = NULL;
}

static int same(const char *a, const char *b, int n) {
  for (int i = 0; i < n; i++) {
    if (a[i] != b[i]) return 0;
  }
  return 1;
}

int __cdecl ntdll_main(void) {
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  int ok = 0;

  NtCreateFileFn create = ntdll
      ? (NtCreateFileFn)GetProcAddress(ntdll, "NtCreateFile") : 0;
  NtOpenFileFn open = ntdll
      ? (NtOpenFileFn)GetProcAddress(ntdll, "NtOpenFile") : 0;
  NtReadFileFn read = ntdll
      ? (NtReadFileFn)GetProcAddress(ntdll, "NtReadFile") : 0;
  NtCloseFn close = ntdll
      ? (NtCloseFn)GetProcAddress(ntdll, "NtClose") : 0;
  if (!create || !open || !read || !close) {
    put(out, "NTDLL resolve=FAIL\n", 19);
    return 1;
  }

  /* Virtual path through the native API. No such directory exists on disk. */
  WCHAR vpath[] = L"\\??\\C:\\virt\\hello.txt";
  UNICODE_STRING vname;
  OBJECT_ATTRIBUTES voa;
  IO_STATUS_BLOCK viosb = {0};
  HANDLE vh = INVALID_HANDLE_VALUE;
  init_us(&vname, vpath);
  init_oa(&voa, &vname);
  LONG st = create(&vh, GENERIC_READ, &voa, &viosb, NULL,
                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                   FILE_NON_DIRECTORY_FILE, NULL, 0);
  char buf[128] = {0};
  IO_STATUS_BLOCK riosb = {0};
  if (st == 0 && vh != INVALID_HANDLE_VALUE) {
    st = read(vh, NULL, NULL, NULL, &riosb, buf, sizeof(buf) - 1,
              NULL, NULL);
  }
  static const char expected[] = "VIRTUAL-FS-OK";
  if (st == 0 && same(buf, expected, sizeof(expected) - 1)) {
    put(out, "NTDLL virtual=OK\n", 17);
    ok = 1;
  } else {
    put(out, "NTDLL virtual=FAIL\n", 19);
  }
  if (vh != INVALID_HANDLE_VALUE) (void)close(vh);

  /* Same path family, but a real file: fall-through must still reach NTFS. */
  WCHAR rpath[] = L"\\??\\C:\\Windows\\win.ini";
  UNICODE_STRING rname;
  OBJECT_ATTRIBUTES roa;
  IO_STATUS_BLOCK riosb2 = {0};
  HANDLE rh = INVALID_HANDLE_VALUE;
  init_us(&rname, rpath);
  init_oa(&roa, &rname);
  LONG rst = open(&rh, GENERIC_READ, &roa, &riosb2, FILE_SHARE_READ,
                  FILE_NON_DIRECTORY_FILE);
  char rbuf[16] = {0};
  IO_STATUS_BLOCK rb = {0};
  if (rst == 0 && rh != INVALID_HANDLE_VALUE) {
    rst = read(rh, NULL, NULL, NULL, &rb, rbuf, sizeof(rbuf) - 1,
               NULL, NULL);
  }
  if (rst == 0 && rb.Information > 0 && rbuf[0] != 0) {
    put(out, "NTDLL fallback=OK\n", 18);
  } else {
    put(out, "NTDLL fallback=FAIL\n", 20);
    ok = 0;
  }
  if (rh != INVALID_HANDLE_VALUE) (void)close(rh);

  put(out, ok ? "NTDLL TARGET OK\n" : "NTDLL TARGET FAIL\n",
      ok ? 16 : 18);
  return ok ? 0 : 1;
}
