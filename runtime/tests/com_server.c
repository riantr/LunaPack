/* L5 test component: a real in-proc COM server, built without the CRT.
 *
 * It is a genuine COM server, not a stand-in: it exports DllGetClassObject,
 * DllCanUnloadNow, DllRegisterServer and DllUnregisterServer, and it hands out
 * an IClassFactory that creates an object with one custom method. COM itself
 * activates it through CoCreateInstance once the class is registered.
 *
 * It has a real DllMain, and DllGetClassObject refuses to hand out a factory
 * until that DllMain has run (g_attached). A manually mapped image is not in
 * the loader's module list, so nothing calls DllMain unless the runtime does:
 * the object therefore only appears when the runtime ran the entry point, which
 * is what makes "the component was initialised" a checkable fact rather than an
 * assumption.
 *
 * No CRT is linked, on purpose: the image has to work from its exported entry
 * points alone, because a hand-mapped image never runs CRT initialisation. That
 * is a real constraint of the L5 design and is written down in
 * runtime/README.md, not worked around here.
 *
 * Registration goes into whatever registry the process sees. Under the
 * runtime that is the in-memory hive, which is why no administrator rights are
 * needed: HKCR looks like a normal writable key.
 */
#include <windows.h>

/* Set by DllMain(DLL_PROCESS_ATTACH). See the note above. */
static int g_attached = 0;

/* The HINSTANCE the loader (or the runtime, for a mapped image) passed in. A
 * component built the ordinary way -- com_server_crt.c -- registers itself with
 * the path this module reports, not with a hard-coded string. */
static HINSTANCE g_hinst = NULL;

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    g_attached = 1;
    g_hinst = module;
  }
  return TRUE;
}

/* {9B1F0A4C-2D3E-4A55-8F01-112233445566} */
static const GUID CLSID_LpAnswer = {0x9b1f0a4c, 0x2d3e, 0x4a55,
                                    {0x8f, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
/* {9B1F0A4D-2D3E-4A55-8F01-112233445566} */
static const GUID IID_ILpAnswer = {0x9b1f0a4d, 0x2d3e, 0x4a55,
                                   {0x8f, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};

/* The two interface ids COM itself uses. They are written out instead of taken
 * from uuid.lib because this component links no libraries beyond kernel32 and
 * advapi32: there is no CRT to pull them in. */
static const GUID k_iid_unknown = {0x00000000, 0x0000, 0x0000,
                                   {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID k_iid_class_factory = {0x00000001, 0x0000, 0x0000,
                                         {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

#define ANSWER 4242

typedef struct ILpAnswer ILpAnswer;
typedef struct ILpAnswerVtbl {
  HRESULT(STDMETHODCALLTYPE *QueryInterface)(ILpAnswer *, const IID *, void **);
  ULONG(STDMETHODCALLTYPE *AddRef)(ILpAnswer *);
  ULONG(STDMETHODCALLTYPE *Release)(ILpAnswer *);
  HRESULT(STDMETHODCALLTYPE *GetAnswer)(ILpAnswer *, int *);
} ILpAnswerVtbl;

struct ILpAnswer {
  const ILpAnswerVtbl *lpVtbl;
  LONG ref;
};

static int guid_eq(const GUID *a, const GUID *b) {
  const unsigned char *x = (const unsigned char *)a;
  const unsigned char *y = (const unsigned char *)b;
  for (int i = 0; i < 16; i++) {
    if (x[i] != y[i]) return 0;
  }
  return 1;
}

static unsigned int wlen(const wchar_t *s) {
  unsigned int n = 0;
  while (s && s[n]) n++;
  return n;
}

/* --------------------------------------------------------- the object --- */

static HRESULT STDMETHODCALLTYPE obj_query(ILpAnswer *self, const IID *riid, void **out) {
  if (!out) return E_POINTER;
  *out = NULL;
  if (guid_eq(riid, &IID_ILpAnswer) || guid_eq(riid, &k_iid_unknown)) {
    self->ref++;
    *out = self;
    return S_OK;
  }
  return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE obj_addref(ILpAnswer *self) {
  return (ULONG)++self->ref;
}

static ULONG STDMETHODCALLTYPE obj_release(ILpAnswer *self) {
  if (--self->ref <= 0) {
    self->ref = 0;
    return 0;
  }
  return (ULONG)self->ref;
}

static HRESULT STDMETHODCALLTYPE obj_answer(ILpAnswer *self, int *out) {
  (void)self;
  if (!out) return E_POINTER;
  *out = ANSWER;
  return S_OK;
}

static const ILpAnswerVtbl obj_vtbl = {obj_query, obj_addref, obj_release, obj_answer};

/* One instance is enough for the test and keeps the component free of any
 * allocator. */
static ILpAnswer g_object = {&obj_vtbl, 1};

/* -------------------------------------------------------- the factory --- */

typedef struct {
  const IClassFactoryVtbl *lpVtbl;
  LONG ref;
} LpFactory;

static HRESULT STDMETHODCALLTYPE fac_query(IClassFactory *self, const IID *riid, void **out) {
  if (!out) return E_POINTER;
  *out = NULL;
  if (guid_eq(riid, &k_iid_unknown) || guid_eq(riid, &k_iid_class_factory)) {
    self->lpVtbl->AddRef(self);
    *out = self;
    return S_OK;
  }
  return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE fac_addref(IClassFactory *self) {
  return (ULONG)++((LpFactory *)self)->ref;
}

static ULONG STDMETHODCALLTYPE fac_release(IClassFactory *self) {
  LpFactory *f = (LpFactory *)self;
  if (--f->ref <= 0) {
    f->ref = 1;
    return 0;
  }
  return (ULONG)f->ref;
}

static HRESULT STDMETHODCALLTYPE fac_create(IClassFactory *self, IUnknown *outer, const IID *riid,
                                            void **out) {
  (void)self;
  if (outer) return CLASS_E_NOAGGREGATION;
  return obj_query(&g_object, riid, out);
}

static HRESULT STDMETHODCALLTYPE fac_lock(IClassFactory *self, BOOL lock) {
  (void)self;
  (void)lock;
  return S_OK;
}

static const IClassFactoryVtbl fac_vtbl = {fac_query, fac_addref, fac_release,
                                           fac_create, fac_lock};

static LpFactory g_factory = {&fac_vtbl, 1};

/* --------------------------------------------------------- the exports --- */

HRESULT __stdcall DllGetClassObject(const GUID *clsid, const GUID *riid, void **out) {
  if (!out) return E_POINTER;
  *out = NULL;
  /* Proof that the runtime ran our entry point before handing us to COM. */
  if (!g_attached) return E_UNEXPECTED;
  if (!guid_eq(clsid, &CLSID_LpAnswer)) return CLASS_E_CLASSNOTAVAILABLE;
  return fac_query((IClassFactory *)&g_factory, riid, out);
}

HRESULT __stdcall DllCanUnloadNow(void) { return S_FALSE; }

/* ------------------------------------------------------ registration --- */

static const wchar_t *CLSID_KEY = L"CLSID\\{9B1F0A4C-2D3E-4A55-8F01-112233445566}";
static const wchar_t *PROGID_KEY = L"LunaPack.Answer";
#ifdef LP_CRT
/* The ordinary build: a component asks the system where it is and registers
 * that answer, exactly as a shipped server does. Under the runtime the answer
 * comes from the virtual filesystem, so the class ends up pointing back into
 * the archive even though the file was never unpacked.
 *
 * The fallback is deliberately a path that is NOT in the archive: if
 * GetModuleFileNameW were answered by the loader instead of the runtime, the
 * registration would point at a file that does not exist and activation would
 * fail. Success therefore proves the runtime answered the question. */
static wchar_t g_module_path[MAX_PATH];
static const wchar_t *module_path(void) {
  DWORD n = g_hinst ? GetModuleFileNameW(g_hinst, g_module_path, MAX_PATH) : 0;
  if (n == 0) return L"C:\\virt\\no-such-module.dll";
  return g_module_path;
}
#else
static const wchar_t *module_path(void) { return L"C:\\virt\\com_server.dll"; }
#endif

static LSTATUS set_sz(HKEY key, const wchar_t *name, const wchar_t *value) {
  return RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value,
                        (DWORD)((wlen(value) + 1) * sizeof(wchar_t)));
}

HRESULT __stdcall DllRegisterServer(void) {
  HKEY cls = NULL, inproc = NULL, prog = NULL, prog_clsid = NULL;
  LSTATUS st;

  st = RegCreateKeyExW(HKEY_CLASSES_ROOT, CLSID_KEY, 0, NULL, 0, KEY_WRITE, NULL, &cls, NULL);
  if (st != ERROR_SUCCESS) return HRESULT_FROM_WIN32(st) & 0xFFFFFFFF;
  st = set_sz(cls, NULL, L"LunaPack answer object");
  if (st == ERROR_SUCCESS) {
    st = RegCreateKeyExW(cls, L"InprocServer32", 0, NULL, 0, KEY_WRITE, NULL, &inproc, NULL);
  }
  if (st == ERROR_SUCCESS) {
    st = set_sz(inproc, NULL, module_path());
    if (st == ERROR_SUCCESS) st = set_sz(inproc, L"ThreadingModel", L"Both");
    RegCloseKey(inproc);
  }
  RegCloseKey(cls);
  if (st != ERROR_SUCCESS) return HRESULT_FROM_WIN32(st) & 0xFFFFFFFF;

  st = RegCreateKeyExW(HKEY_CLASSES_ROOT, PROGID_KEY, 0, NULL, 0, KEY_WRITE, NULL, &prog, NULL);
  if (st != ERROR_SUCCESS) return HRESULT_FROM_WIN32(st) & 0xFFFFFFFF;
  st = set_sz(prog, NULL, L"LunaPack answer object");
  if (st == ERROR_SUCCESS) {
    st = RegCreateKeyExW(prog, L"CLSID", 0, NULL, 0, KEY_WRITE, NULL, &prog_clsid, NULL);
  }
  if (st == ERROR_SUCCESS) {
    st = set_sz(prog_clsid, NULL, L"{9B1F0A4C-2D3E-4A55-8F01-112233445566}");
    RegCloseKey(prog_clsid);
  }
  RegCloseKey(prog);
  return st == ERROR_SUCCESS ? S_OK : (HRESULT_FROM_WIN32(st) & 0xFFFFFFFF);
}

HRESULT __stdcall DllUnregisterServer(void) {
  RegDeleteKeyW(HKEY_CLASSES_ROOT, CLSID_KEY);
  RegDeleteKeyW(HKEY_CLASSES_ROOT, L"CLSID\\{9B1F0A4C-2D3E-4A55-8F01-112233445566}\\InprocServer32");
  RegDeleteKeyW(HKEY_CLASSES_ROOT, PROGID_KEY);
  RegDeleteKeyW(HKEY_CLASSES_ROOT, L"LunaPack.Answer\\CLSID");
  return S_OK;
}
