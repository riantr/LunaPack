// L2.3 spike: ntdll-boundary interception with virtual-first semantics.
//
// The existing runtime patches application IATs at the Win32 layer. A program
// that resolves NtCreateFile/NtOpenFile/NtReadFile itself (or imports them
// statically from ntdll.dll) bypasses every one of those slots. This module
// closes that specific gap WITHOUT an inline code hook: the four native entry
// points are added to the same hook table, so a mapped image's static imports
// and our GetProcAddress thunk both route them here.
//
// The VFS still owns the requested bytes: no file is written to disk, no
// remote process is touched, and every unsupported call falls through to the
// real Win32 API through lpvirt.dll's own unpatched imports. Any inline patch
// of ntdll.dll itself remains a separate, AV-gated decision (see AV_RETEST).

///|
const STATUS_SUCCESS : Int32 = 0

///|
const STATUS_UNSUCCESSFUL : Int32 = -1073741823 // 0xC0000001

///|
const STATUS_INVALID_HANDLE : Int32 = -1073741816 // 0xC0000008

///|
const STATUS_ACCESS_DENIED_NT : Int32 = -1073741790 // 0xC0000022

///|
const STATUS_OBJECT_NAME_NOT_FOUND : Int32 = -1073741772 // 0xC0000034

///|
const STATUS_OBJECT_NAME_COLLISION : Int32 = -1073741771 // 0xC0000035

///|
const ERROR_ACCESS_DENIED_WIN32 : Int32 = 5

///|
const ERROR_FILE_EXISTS_WIN32 : Int32 = 80

///|
/// NT CreateDisposition values.
const FILE_SUPERSEDE : Int32 = 0

///|
const FILE_OPEN : Int32 = 1

///|
const FILE_CREATE : Int32 = 2

///|
const FILE_OPEN_IF : Int32 = 3

///|
const FILE_OVERWRITE : Int32 = 4

///|
const FILE_OVERWRITE_IF : Int32 = 5

///|
extern "C" fn get_last_error() -> Int32 = "GetLastError"

///|
/// Extract the object name from OBJECT_ATTRIBUTES and strip the NT prefixes
/// that Vfs::norm_path does not understand. On x64 the layout is
/// Length@0 (4), padding@4, RootDirectory@8, ObjectName@16.
fn nt_object_path(obj : Int64) -> String {
  if obj == 0L {
    return ""
  }
  let name = peek64(obj + 16L)
  if name == 0L {
    return ""
  }
  let len = peek16(name)
  let buf = peek64(name + 8L)
  nt_strip_prefix(wide_exact(buf, len))
}

///|
/// The prefix stripping is pure so the white-box tests can exercise it
/// without touching Win32 memory.
fn nt_strip_prefix(raw : String) -> String {
  if raw.has_prefix("\\??\\") {
    str_slice(raw, 4, raw.length())
  } else if raw.has_prefix("\\DosDevices\\") {
    str_slice(raw, 12, raw.length())
  } else if raw.has_prefix("\\\\?\\") {
    str_slice(raw, 4, raw.length())
  } else if raw.has_prefix("\\\\.\\") {
    str_slice(raw, 4, raw.length())
  } else {
    raw
  }
}

///|
fn nt_disposition(d : Int32) -> Int32 {
  if d == FILE_SUPERSEDE {
    CREATE_ALWAYS
  } else if d == FILE_CREATE {
    CREATE_NEW
  } else if d == FILE_OPEN_IF {
    OPEN_ALWAYS
  } else if d == FILE_OVERWRITE {
    TRUNCATE_EXISTING
  } else if d == FILE_OVERWRITE_IF {
    CREATE_ALWAYS
  } else {
    OPEN_EXISTING
  }
}

///|
fn nt_from_win32(code : Int32) -> Int32 {
  if code == ERROR_SUCCESS {
    STATUS_SUCCESS
  } else if code == ERROR_FILE_NOT_FOUND {
    STATUS_OBJECT_NAME_NOT_FOUND
  } else if code == ERROR_ACCESS_DENIED_WIN32 {
    STATUS_ACCESS_DENIED_NT
  } else if code == ERROR_FILE_EXISTS_WIN32 {
    STATUS_OBJECT_NAME_COLLISION
  } else {
    STATUS_UNSUCCESSFUL
  }
}

///|
/// Write the 64-bit Information field of an IO_STATUS_BLOCK (x64 offset 8).
fn nt_set_information(iosb : Int64, bytes : Int64) -> Unit {
  if iosb != 0L {
    poke_bytes(iosb + 8L, u64le(bytes), 8)
  }
}

///|
/// Scratch buffer for a NUL-terminated wide path passed to the real Win32 API.
/// One short-lived VirtualAlloc in our own process, released by the caller.
fn nt_wide_scratch(s : String) -> Int64 {
  let w = utf16le(s)
  let p = virtual_alloc(0L, w.length().to_int64(), MEM_COMMIT, PAGE_READWRITE)
  if p == 0L {
    return 0L
  }
  poke_bytes(p, w, w.length())
  p
}

///|
/// NtCreateFile. Virtual paths get a VFS handle and a synthetic NTSTATUS;
/// everything else is forwarded to the real CreateFileW. This is the fallback
/// used by direct-callers (static ntdll imports / GetProcAddress), NOT by a
/// patch of kernel32/KernelBase internals - see the L2.3 note in the TODO.
#export_name("lp_nt_create_file")
pub fn lp_nt_create_file(
  file_handle : Int64,
  desired_access : Int32,
  object_attributes : Int64,
  io_status : Int64,
  allocation_size : Int64,
  file_attributes : Int32,
  share_access : Int32,
  create_disposition : Int32,
  create_options : Int32,
  ea_buffer : Int64,
  ea_length : Int32,
) -> Int32 {
  // The native ABI requires these slots even though the VFS does not use them
  // yet; acknowledge them so the static gate stays at actionable=0.
  ignore(allocation_size)
  ignore(create_options)
  ignore(ea_buffer)
  ignore(ea_length)
  let path = nt_object_path(object_attributes)
  let disp = nt_disposition(create_disposition)
  match state_vfs().create_file(path, desired_access, disp) {
    Opened(h) => {
      state_vfs().note_create()
      g_runtime.ntdll_hits = g_runtime.ntdll_hits + 1
      if file_handle != 0L {
        poke_bytes(file_handle, u64le(h), 8)
      }
      nt_set_information(io_status, 1L)
      STATUS_SUCCESS
    }
    Failed(code) => nt_from_win32(code)
    NotVirtual => {
      let raw = nt_wide_scratch(path)
      if raw == 0L {
        return STATUS_UNSUCCESSFUL
      }
      let h = real_create_file_w(
        raw, desired_access, share_access, 0L, disp, file_attributes, 0L,
      )
      ignore(virtual_free(raw, 0L, MEM_RELEASE))
      if h == INVALID_HANDLE_VALUE {
        nt_from_win32(get_last_error())
      } else {
        if file_handle != 0L {
          poke_bytes(file_handle, u64le(h), 8)
        }
        nt_set_information(io_status, 1L)
        STATUS_SUCCESS
      }
    }
  }
}

///|
/// NtOpenFile: the same virtual-first path with OPEN_EXISTING semantics.
#export_name("lp_nt_open_file")
pub fn lp_nt_open_file(
  file_handle : Int64,
  desired_access : Int32,
  object_attributes : Int64,
  io_status : Int64,
  share_access : Int32,
  open_options : Int32,
) -> Int32 {
  ignore(open_options)
  let path = nt_object_path(object_attributes)
  match state_vfs().create_file(path, desired_access, OPEN_EXISTING) {
    Opened(h) => {
      state_vfs().note_create()
      g_runtime.ntdll_hits = g_runtime.ntdll_hits + 1
      if file_handle != 0L {
        poke_bytes(file_handle, u64le(h), 8)
      }
      nt_set_information(io_status, 1L)
      STATUS_SUCCESS
    }
    Failed(code) => nt_from_win32(code)
    NotVirtual => {
      let raw = nt_wide_scratch(path)
      if raw == 0L {
        return STATUS_UNSUCCESSFUL
      }
      let h = real_create_file_w(
        raw,
        desired_access,
        share_access,
        0L,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0L,
      )
      ignore(virtual_free(raw, 0L, MEM_RELEASE))
      if h == INVALID_HANDLE_VALUE {
        nt_from_win32(get_last_error())
      } else {
        if file_handle != 0L {
          poke_bytes(file_handle, u64le(h), 8)
        }
        nt_set_information(io_status, 1L)
        STATUS_SUCCESS
      }
    }
  }
}

///|
/// NtReadFile. A VFS handle is recognized by Vfs::read; any other handle is
/// forwarded to the real ReadFile. An explicit ByteOffset is expressed as a
/// stack-local OVERLAPPED so the positioned-read contract is preserved.
#export_name("lp_nt_read_file")
pub fn lp_nt_read_file(
  handle : Int64,
  event : Int64,
  apc_routine : Int64,
  apc_context : Int64,
  io_status : Int64,
  buffer : Int64,
  length : Int32,
  byte_offset : Int64,
  key : Int64,
) -> Int32 {
  ignore(apc_routine)
  ignore(apc_context)
  ignore(key)
  let v = state_vfs()
  let data = if byte_offset != 0L {
    v.read_at(handle, length, peek64(byte_offset))
  } else {
    v.read(handle, length)
  }
  match data {
    Some(bytes) => {
      if buffer != 0L {
        poke_bytes(buffer, bytes, bytes.length())
      }
      g_runtime.ntdll_hits = g_runtime.ntdll_hits + 1
      nt_set_information(io_status, bytes.length().to_int64())
      STATUS_SUCCESS
    }
    None => {
      let written = if io_status == 0L { 0L } else { io_status + 8L }
      nt_set_information(io_status, 0L)
      if byte_offset == 0L {
        let ok = real_read_file(handle, buffer, length, written, 0L)
        if ok != 0 {
          STATUS_SUCCESS
        } else {
          nt_from_win32(get_last_error())
        }
      } else {
        let ov = virtual_alloc(0L, 40L, MEM_COMMIT, PAGE_READWRITE)
        if ov == 0L {
          return STATUS_UNSUCCESSFUL
        }
        let zero = Bytes::make(40, b'\x00')
        poke_bytes(ov, zero, 40)
        let off = peek64(byte_offset)
        poke_bytes(ov + 16L, u32le(off & 0xFFFFFFFFL), 4)
        poke_bytes(ov + 20L, u32le((off >> 32) & 0xFFFFFFFFL), 4)
        poke_bytes(ov + 24L, u64le(event), 8)
        let ok = real_read_file(handle, buffer, length, written, ov)
        if ok != 0 && io_status != 0L {
          poke_bytes(io_status, peek_bytes(ov, 8), 8)
          poke_bytes(io_status + 8L, peek_bytes(ov + 8L, 8), 8)
        }
        ignore(virtual_free(ov, 0L, MEM_RELEASE))
        if ok != 0 {
          STATUS_SUCCESS
        } else {
          nt_from_win32(get_last_error())
        }
      }
    }
  }
}

///|
/// NtClose: virtual handles must not reach the real kernel.
#export_name("lp_nt_close")
pub fn lp_nt_close(handle : Int64) -> Int32 {
  if state_reg().close_key(handle) {
    g_runtime.ntdll_hits = g_runtime.ntdll_hits + 1
    return STATUS_SUCCESS
  }
  if state_vfs().close(handle) {
    g_runtime.ntdll_hits = g_runtime.ntdll_hits + 1
    STATUS_SUCCESS
  } else {
    let ok = real_close_handle(handle)
    if ok != 0 {
      STATUS_SUCCESS
    } else {
      STATUS_INVALID_HANDLE
    }
  }
}

///|
/// Number of calls served at the ntdll boundary. Exposed through lp_virt_stats
/// as slot 12 (requires a 52-byte output buffer).
#export_name("lp_virt_ntdll_stats")
pub fn lp_virt_ntdll_stats() -> Int32 {
  g_runtime.ntdll_hits
}
