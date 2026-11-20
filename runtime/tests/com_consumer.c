/* L5 test consumer: activate the component through real COM.
 *
 * Built without the CRT with /ENTRY:com_main, so the host can map it and call
 * the entry point directly. Every call that reaches the registry or the loader
 * is made by combase, not by this program: that is the whole point. If the
 * class is found, the server was mapped from the virtual filesystem and COM
 * called its DllGetClassObject.
 */
#include <windows.h>
#include <oleauto.h>

static void put(const char *s, int n) {
  DWORD wrote = 0;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, (DWORD)n, &wrote, NULL);
}

static void say(const char *s) { put(s, lstrlenA(s)); }

static void say_int(long v) {
  char buf[12];
  int i = 0;
  unsigned long u;
  if (v < 0) {
    put("-", 1);
    u = (unsigned long)(-v);
  } else {
    u = (unsigned long)v;
  }
  if (u == 0) {
    put("0", 1);
    return;
  }
  while (u > 0 && i < (int)sizeof(buf)) {
    buf[i++] = (char)('0' + (u % 10));
    u /= 10;
  }
  while (i > 0) {
    put(&buf[--i], 1);
  }
}

static void say_hex(unsigned long v) {
  char buf[8];
  for (int i = 7; i >= 0; i--) {
    unsigned int nib = (unsigned int)(v & 0xf);
    buf[i] = (char)(nib < 10 ? '0' + nib : 'a' + (nib - 10));
    v >>= 4;
  }
  put(buf, 8);
}

/* {9B1F0A4C-2D3E-4A55-8F01-112233445566} */
static const GUID CLSID_LpAnswer = {0x9b1f0a4c, 0x2d3e, 0x4a55,
                                    {0x8f, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
/* {9B1F0A4D-2D3E-4A55-8F01-112233445566} */
static const GUID IID_ILpAnswer = {0x9b1f0a4d, 0x2d3e, 0x4a55,
                                   {0x8f, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};

typedef struct ILpAnswer ILpAnswer;
typedef struct ILpAnswerVtbl {
  HRESULT(STDMETHODCALLTYPE *QueryInterface)(ILpAnswer *, const IID *, void **);
  ULONG(STDMETHODCALLTYPE *AddRef)(ILpAnswer *);
  ULONG(STDMETHODCALLTYPE *Release)(ILpAnswer *);
  HRESULT(STDMETHODCALLTYPE *GetAnswer)(ILpAnswer *, int *);
} ILpAnswerVtbl;

struct ILpAnswer {
  const ILpAnswerVtbl *lpVtbl;
};

/* {A1B2C3D4-0001-4000-9000-000000000001} -- the LIBID in com_server.idl. */
static const GUID LIBID_LunaPackAnswer = {
    0xa1b2c3d4, 0x0001, 0x4000, {0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};

/* The first four slots of ITypeLib, spelled out. The SDK header declares
 * GetTypeInfoCount without its out-parameter (a midl quirk for this
 * interface), so calling it through that declaration would leave the argument
 * register holding whatever was there before. The real ABI takes the pointer. */
typedef struct LpTypeLib LpTypeLib;
typedef struct LpTypeLibVtbl {
  HRESULT(STDMETHODCALLTYPE *QueryInterface)(LpTypeLib *, const IID *, void **);
  ULONG(STDMETHODCALLTYPE *AddRef)(LpTypeLib *);
  ULONG(STDMETHODCALLTYPE *Release)(LpTypeLib *);
  HRESULT(STDMETHODCALLTYPE *GetTypeInfoCount)(LpTypeLib *, UINT *);
} LpTypeLibVtbl;

struct LpTypeLib {
  const LpTypeLibVtbl *lpVtbl;
};

int com_main(void) {
  HRESULT hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  say("COM init=0x");
  say_hex((unsigned long)hr_init);
  say("\n");

  /* The type library the server registered is loadable by identifier. The
   * registry entry points at a path with no file behind it, so this only works
   * because the runtime kept the parsed library and answers for it. */
  ITypeLib *tl = NULL;
  HRESULT hr_tlb = LoadRegTypeLib(&LIBID_LunaPackAnswer, 1, 0, 1033, &tl);
  say("REG load=0x");
  say_hex((unsigned long)hr_tlb);
  say("\n");
  if (SUCCEEDED(hr_tlb) && tl) {
    LpTypeLib *lib = (LpTypeLib *)tl;
    UINT count = 0;
    HRESULT hr_count = lib->lpVtbl->GetTypeInfoCount(lib, &count);
    say("REG count=");
    say_int((long)count);
    say(" hr=0x");
    say_hex((unsigned long)hr_count);
    say("\n");
    lib->lpVtbl->Release(lib);
  }

  ILpAnswer *obj = NULL;
  HRESULT hr = CoCreateInstance(&CLSID_LpAnswer, NULL, CLSCTX_INPROC_SERVER, &IID_ILpAnswer,
                                (void **)&obj);
  say("COM create=0x");
  say_hex((unsigned long)hr);
  say("\n");
  if (hr != S_OK || !obj) {
    say("COM answer=NONE\n");
    return 1;
  }
  int value = 0;
  HRESULT hr2 = obj->lpVtbl->GetAnswer(obj, &value);
  say("COM call=0x");
  say_hex((unsigned long)hr2);
  say("\n");
  if (hr2 == S_OK) {
    say("COM answer=");
    say_int(value);
    say("\n");
  } else {
    say("COM answer=NONE\n");
  }
  obj->lpVtbl->Release(obj);
  CoUninitialize();
  return hr2 == S_OK ? 0 : 1;
}
