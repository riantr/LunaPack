/* L5 test consumer: activate the component through real COM.
 *
 * Built without the CRT with /ENTRY:com_main, so the host can map it and call
 * the entry point directly. Every call that reaches the registry or the loader
 * is made by combase, not by this program: that is the whole point. If the
 * class is found, the server was mapped from the virtual filesystem and COM
 * called its DllGetClassObject.
 */
#include <windows.h>

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

int com_main(void) {
  HRESULT hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  say("COM init=0x");
  say_hex((unsigned long)hr_init);
  say("\n");

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
