// Give the produced bundle the icon of the application it carries.
//
// The icon is read from the application executable with the PE reader and
// written into the bundle with the Windows resource API. That API creates the
// resource section when the target file does not have one yet, which is the
// case for the MoonBit launcher stub.
//
// The feature is Windows only; on other platforms the bundle simply keeps
// the icon of the launcher.

///|
/// Encode a String as a NUL terminated UTF-16LE buffer, for the wide
/// Windows APIs.
fn utf16_z(s : String) -> Bytes {
  let arr = []
  for ch in s.iter() {
    let cp = ch.to_int()
    if cp < 0x10000 {
      arr.push((cp & 0xff).to_byte())
      arr.push(((cp >> 8) & 0xff).to_byte())
    } else {
      // Surrogate pair for the code points above the basic plane.
      let v = cp - 0x10000
      let hi = 0xd800 + (v >> 10)
      let lo = 0xdc00 + (v & 0x3ff)
      arr.push((hi & 0xff).to_byte())
      arr.push(((hi >> 8) & 0xff).to_byte())
      arr.push((lo & 0xff).to_byte())
      arr.push(((lo >> 8) & 0xff).to_byte())
    }
  }
  arr.push(b'\x00')
  arr.push(b'\x00')
  Bytes::from_array(arr)
}

///|
/// Copy the icon of `source_exe` into `target_exe`.
///
/// Returns true when the icon was copied.
#cfg(platform="windows")
pub async fn copy_icon(source_exe : String, target_exe : String) -> Bool {
  let data = @fs.read_binary(source_exe)
  // A source that is not a PE image, or that carries no icon, simply means
  // there is nothing to copy.
  let pe = parse_pe(data) catch { _ => return false }
  let (group_id, group, icons) = match extract_icon(pe) {
    Some(x) => x
    None => return false
  }
  let handle = begin_update_resource_w(utf16_z(target_exe), 0)
  if handle == 0 {
    return false
  }
  let mut ok = true
  for i in icons {
    let r = update_resource_w(handle, RT_ICON, i.0, 0, i.1, i.1.length())
    if r == 0 {
      ok = false
    }
  }
  let r = update_resource_w(
    handle,
    RT_GROUP_ICON,
    group_id,
    0,
    group,
    group.length(),
  )
  if r == 0 {
    ok = false
  }
  let _ = end_update_resource_w(handle, 0)
  ok
}

///|
/// Copy the icon of `source_exe` into `target_exe`.
///
/// The icon is a Windows resource, so this is a no-op elsewhere.
#cfg(not(platform="windows"))
pub async fn copy_icon(_source_exe : String, _target_exe : String) -> Bool {
  false
}

///|
#cfg(platform="windows")
#borrow(path)
extern "C" fn begin_update_resource_w(
  path : Bytes,
  delete_existing : Int32,
) -> Int64 = "BeginUpdateResourceW"

///|
#cfg(platform="windows")
#borrow(data)
extern "C" fn update_resource_w(
  handle : Int64,
  rtype : Int64,
  name : Int64,
  lang : Int32,
  data : Bytes,
  size : Int32,
) -> Int32 = "UpdateResourceW"

///|
#cfg(platform="windows")
extern "C" fn end_update_resource_w(handle : Int64, discard : Int32) -> Int32 = "EndUpdateResourceW"
