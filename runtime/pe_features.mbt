// L3.3 / L3.4: delay imports, TLS directory and exception (.pdata) directory
// support for the manual PE mapper.
//
// A manually mapped image does not go through the OS loader, so three PE
// features that the loader normally handles are invisible:
//   * delay-loaded imports stay pointing at __delayLoadHelper2;
//   * TLS callbacks never run and the TLS index is never allocated;
//   * SEH unwinding has no function table registered with the kernel.
//
// This module resolves delay imports eagerly into the IAT (through the same
// hook table so virtual-first semantics apply), exposes the TLS directory so
// the host can allocate an index and run callbacks, and registers the .pdata
// exception table with RtlAddFunctionTable for stack unwinding.

///|
/// ImgDelayDescr is 32 bytes on x64. grAttrs bit 0 means the RVA fields really
/// are RVAs (dlattrRva); otherwise they are absolute VAs.
const DLATTR_RVA : Int64 = 1L

///|
const RUNTIME_FUNCTION_SIZE : Int64 = 12L

///|
extern "C" fn rtl_add_function_table(
  table : Int64,
  count : Int32,
  image_base : Int64,
) -> Int32 = "RtlAddFunctionTable"

///|
extern "C" fn rtl_delete_function_table(table : Int64) -> Int32 = "RtlDeleteFunctionTable"

///|
extern "C" fn tls_alloc() -> Int32 = "TlsAlloc"

// ------------------------------------------------ pure directory readers ---

///|
/// Number of ImgDelayDescr entries in the delay-import directory. Pure over
/// the file image so white-box tests can build synthetic descriptors.
fn delay_import_count(layout : ImageLayout) -> Int32 {
  let (rva, size) = dir_entry(layout, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
  if rva == 0L || size < 32L {
    return 0
  }
  let start = match rva_to_file(layout, rva) {
    Some(o) => o
    None => return 0
  }
  let mut cur = start
  let end = if start + size > layout.data.length().to_int64() {
    layout.data.length().to_int64()
  } else {
    start + size
  }
  let mut n = 0
  while cur + 32L <= end {
    let name_rva = img_u32(layout.data, cur + 4L)
    let iat_rva = img_u32(layout.data, cur + 12L)
    if name_rva == 0L && iat_rva == 0L {
      break
    }
    n = n + 1
    cur = cur + 32L
  }
  n
}

///|
/// Does the image declare a TLS directory? Pure reader.
fn has_tls_directory(layout : ImageLayout) -> Bool {
  let (rva, size) = dir_entry(layout, IMAGE_DIRECTORY_ENTRY_TLS)
  rva != 0L && size >= 40L
}

///|
/// Number of RUNTIME_FUNCTION entries in the exception directory. Pure reader.
fn eh_function_count(layout : ImageLayout) -> Int32 {
  let (rva, size) = dir_entry(layout, IMAGE_DIRECTORY_ENTRY_EXCEPTION)
  if rva == 0L || size < RUNTIME_FUNCTION_SIZE {
    return 0
  }
  (size / RUNTIME_FUNCTION_SIZE).to_int()
}

// -------------------------------------------- mapped-image resolvers -------

///|
/// L3.3: eagerly resolve delay imports of a mapped image. For each descriptor
/// we load the provider, walk the INT and write resolved addresses into the
/// IAT. When the imported API is one we virtualize, we install OUR thunk so
/// virtual-first semantics apply from the first call (no __delayLoadHelper2).
/// Returns the number of delay descriptors processed.
fn resolve_delay_imports(layout : ImageLayout, base : Int64) -> Int32 {
  let (rva, size) = dir_entry(layout, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
  if rva == 0L || size < 32L {
    return 0
  }
  let mut cur = match rva_to_file(layout, rva) {
    Some(o) => o
    None => return 0
  }
  let end = cur + size
  let mut descriptors = 0
  while cur + 32L <= end && cur + 32L <= layout.data.length().to_int64() {
    let attrs = img_u32(layout.data, cur)
    let name_rva = img_u32(layout.data, cur + 4L)
    let hmod_rva = img_u32(layout.data, cur + 8L)
    let iat_rva = img_u32(layout.data, cur + 12L)
    let int_rva = img_u32(layout.data, cur + 16L)
    if name_rva == 0L && iat_rva == 0L {
      break
    }
    let name_off = match rva_to_file(layout, name_rva) {
      Some(o) => o
      None => break
    }
    let dll = img_cstr(layout.data, name_off, 128L)
    let handle = load_library_a(cstring(dll))
    if handle == 0L {
      break
    }
    let rva_based = (attrs & DLATTR_RVA) != 0L
    // Record the provider HMODULE where the image expects it.
    if hmod_rva != 0L {
      let hmod_addr = if rva_based { base + hmod_rva } else { hmod_rva }
      poke64(hmod_addr, handle)
    }
    let lookup_off = match rva_to_file(layout, int_rva) {
      Some(o) => o
      None => break
    }
    let mut i = 0L
    while i < 4096L {
      let entry = img_u64(layout.data, lookup_off + i * 8L)
      if entry == 0L {
        break
      }
      let target = if entry < 0L {
        resolve_import_ordinal(handle, ordinal_from_thunk(entry))
      } else {
        let hint_off = match rva_to_file(layout, entry & 0xffffffffL) {
          Some(o) => o
          None => break
        }
        let api = img_cstr(layout.data, hint_off + 2L, 128L)
        // Virtual-first: prefer our thunk when the API is in the hook table.
        match lookup_thunk(api) {
          Some(thunk_name) => {
            let our = thunk_address(thunk_name)
            if our != 0L {
              our
            } else {
              real_get_proc_address(handle, cstring(api))
            }
          }
          None => real_get_proc_address(handle, cstring(api))
        }
      }
      if target != 0L {
        let slot = if rva_based {
          base + iat_rva + i * 8L
        } else {
          iat_rva + i * 8L
        }
        poke64(slot, target)
      }
      i = i + 1L
    }
    descriptors = descriptors + 1
    cur = cur + 32L
  }
  descriptors
}

///|
/// L3.4: allocate a TLS index for a mapped image and return the VA of its
/// callback array (null-terminated list of function pointers). The host calls
/// each callback with (base, DLL_PROCESS_ATTACH/DETACH, NULL). Returns 0 when
/// the image has no TLS directory or no callbacks.
#export_name("lp_get_tls_callbacks")
pub fn lp_get_tls_callbacks(base : Int64) -> Int64 {
  if base == 0L || peek16(base) != 0x5a4d {
    return 0L
  }
  let pe_off = peek32(base + 0x3cL)
  let opt = base + pe_off + 24L
  if peek16(opt) != 0x20b {
    return 0L
  }
  let tls_rva = peek32(opt + 112L + IMAGE_DIRECTORY_ENTRY_TLS.to_int64() * 8L)
  if tls_rva == 0L {
    return 0L
  }
  let tls = base + tls_rva
  // IMAGE_TLS_DIRECTORY64: AddressOfIndex@16, AddressOfCallBacks@24.
  let index_va = peek64(tls + 16L)
  let callbacks_va = peek64(tls + 24L)
  if index_va != 0L {
    let idx = tls_alloc()
    poke_bytes(index_va, u32le(idx.to_int64()), 4)
  }
  callbacks_va
}

///|
/// L3.4: register the .pdata exception directory of a mapped image so SEH
/// unwinding works for code running inside it. Returns 1 on success, 0 if the
/// image has no exception directory or registration failed. The table must be
/// released with lp_unregister_eh before the image is unmapped.
#export_name("lp_register_eh")
pub fn lp_register_eh(base : Int64) -> Int32 {
  if base == 0L || peek16(base) != 0x5a4d {
    return 0
  }
  let pe_off = peek32(base + 0x3cL)
  let opt = base + pe_off + 24L
  if peek16(opt) != 0x20b {
    return 0
  }
  let dd = opt + 112L + IMAGE_DIRECTORY_ENTRY_EXCEPTION.to_int64() * 8L
  let eh_rva = peek32(dd)
  let eh_size = peek32(dd + 4L)
  if eh_rva == 0L || eh_size < RUNTIME_FUNCTION_SIZE {
    return 0
  }
  let count = (eh_size / RUNTIME_FUNCTION_SIZE).to_int()
  let table = base + eh_rva
  let ok = rtl_add_function_table(table, count, base) & 0xff
  if ok != 0 {
    g_runtime.eh_table = table
    1
  } else {
    0
  }
}

///|
/// Release the exception table registered by lp_register_eh.
#export_name("lp_unregister_eh")
pub fn lp_unregister_eh(base : Int64) -> Int32 {
  ignore(base)
  if g_runtime.eh_table == 0L {
    return 0
  }
  let ok = rtl_delete_function_table(g_runtime.eh_table) & 0xff
  g_runtime.eh_table = 0L
  ok
}
