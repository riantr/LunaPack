// Dependency discovery.
//
// A Windows program is not one file: it is an executable and the libraries it
// loads. A bundle that carries only the executable starts and then stops
// with STATUS_DLL_NOT_FOUND, and the list of what is missing is written in
// the import table of the executable. This is where that list is read.
//
// What can be found is what the binary says out loud: the libraries it names
// in its import table. What cannot be found is what it opens at runtime with
// LoadLibrary, and every data file it reads; neither is written down
// anywhere, so only the caller can say what those are.

///|
/// The DLLs that a program needs from the folder it sits in.
///
/// The names come from the import table of the program and from the import
/// tables of the libraries it needs in turn. Only the ones that are actually
/// next to the program are returned: a library that is not there is either
/// part of the system or one the program finds somewhere else, and neither is
/// something a bundle can carry.
///
/// The paths that come back are absolute, and they are the files themselves:
/// the ones next to the program, in the order they were found.
pub async fn discover_dependencies(exe : String) -> Array[String] {
  let out = []
  let seen = []
  let dir = folder_of(norm_sep(exe))
  // The folder is looked through once: the name in an import table is
  // spelled the way the library was built, and the file on the disk may be
  // spelled differently.
  let files = @fs.readdir(dir) catch { _ => [] }
  let queue = [norm_sep(exe)]
  while !queue.is_empty() {
    let current = queue.pop().unwrap()
    if seen.contains(current) {
      continue
    }
    seen.push(current)
    for name in imported_dlls(current) {
      // A name of the system is never a file of the program.
      if is_api_set_dll(name) {
        continue
      }
      if is_known_dll(name) {
        continue
      }
      match find_in(files, name) {
        None => ()
        Some(file) => {
          let path = norm_sep(dir + "/" + file)
          if out.contains(path) {
            continue
          }
          out.push(path)
          // A library needs libraries of its own, and they are looked for in
          // the same folder: that is where Windows looks for them too.
          queue.push(path)
        }
      }
    }
  }
  out
}

///|
/// The folder a path is in, and "." for a path without a folder.
fn folder_of(path : String) -> String {
  let dir = dirname(path)
  if dir == "" {
    "."
  } else {
    dir
  }
}

///|
/// The names of the libraries that the file at `path` imports.
///
/// A file that is not a PE image imports nothing, and neither does a file
/// that cannot be read: there is nothing to find in either.
async fn imported_dlls(path : String) -> Array[String] {
  let data = @fs.read_binary(path) catch { _ => return [] }
  let names = pe_import_dlls(data)
  let delayed = pe_delay_import_dlls(data)
  let out = []
  for n in names {
    out.push(n)
  }
  for n in delayed {
    if !out.contains(n) {
      out.push(n)
    }
  }
  out
}

///|
/// The file in `files` that is called `name`.
///
/// The name in an import table is spelled the way the library was built, and
/// the file on the disk may be spelled differently: Windows does not care
/// about the case. The name of the file on the disk is the one that is
/// returned, because that is the name the file has to keep in the bundle.
fn find_in(files : Array[String], name : String) -> String? {
  for f in files {
    if f == name {
      return Some(f)
    }
  }
  for f in files {
    if same_name(f, name) {
      return Some(f)
    }
  }
  None
}

///|
/// Is `name` the name of an API set?
///
/// An API set is a name the system gives to a group of functions, and the
/// library that carries it is a virtual one: there is no such file on the
/// disk, and the system resolves the name to a real library when the
/// program is started. A bundle that carried one would carry nothing.
pub fn is_api_set_dll(name : String) -> Bool {
  starts_with_ignoring_case(name, "api-ms-") ||
  starts_with_ignoring_case(name, "ext-ms-")
}

///|
/// Is `name` a library the system always loads from its own copy?
///
/// The system keeps a list of these, and it loads them from itself whatever
/// the program carries: the file next to the program is never used, so
/// carrying it would only make the bundle bigger.
pub fn is_known_dll(name : String) -> Bool {
  for k in known_dlls() {
    if same_name(k, name) {
      return true
    }
  }
  false
}

///|
/// The libraries the system loads from its own copy.
///
/// This is the list of Windows 10 and 11. It is a list and not a lookup in
/// the registry, because the registry of one machine is not the registry of
/// the machine the bundle is made for, and a bundle that leaves out a library
/// because this machine did not know it would fail on the other one.
fn known_dlls() -> Array[String] {
  [
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "bootvid.dll", "calsrv.dll",
    "cfgmgr32.dll", "clbcatq.dll", "combase.dll", "comdlg32.dll", "compositebus.dll",
    "credui.dll", "crypt32.dll", "cryptsp.dll", "d2d1.dll", "d3d10warp.dll", "d3d11.dll",
    "d3d12.dll", "d3d9.dll", "d3dim.dll", "dcomp.dll", "ddraw.dll", "dhcpapi.dll",
    "dhcpcsvc.dll", "dnsapi.dll", "dsound.dll", "dwrite.dll", "dwritecore.dll", "dxgi.dll",
    "efslsrvapi.dll", "embeddedprovider.dll", "eventvwr.dll", "faults.dll", "fwpuclnt.dll",
    "gdi32.dll", "gdi32full.dll", "gdiplus.dll", "gpapi.dll", "hiddenwindow.dll",
    "hostname.dll", "imm32.dll", "imagehlp.dll", "imeui.dll", "inf.dll", "infascii.dll",
    "integrity.dll", "iphlpapi.dll", "itss.dll", "kernel32.dll", "kernelbase.dll",
    "ksecdd.dll", "licui.dll", "locale.dll", "manpath.dll", "mfplat.dll", "mgdmts.dll",
    "midl.dll", "mpr.dll", "msvcp140.dll", "ncrypt.dll", "nsi.dll", "normaliz.dll",
    "ole32.dll", "oleacdui.dll", "oleaut32.dll", "oledlg.dll", "oledir.dll", "olepro32.dll",
    "olesvr32.dll", "oletypes.dll", "powrprof.dll", "profapi.dll", "propsys.dll",
    "psapi.dll", "pstorec.dll", "psxml.dll", "rasapi32.dll", "rpcrt4.dll", "sechost.dll",
    "sensapi.dll", "shcore.dll", "shell32.dll", "shfolder.dll", "shlwapi.dll", "slwapi.dll",
    "snxhk.dll", "strmdll.dll", "ucrtbase.dll", "user32.dll", "userenv.dll", "wdmsec.dll",
    "winspool.drv", "wldap32.dll", "wtsapi32.dll", "wtvfw32.dll", "xaml.dll", "xmllite.dll",
  ]
}

///|
/// Are the two names the same, whatever the case of the letters?
///
/// Windows does not care about the case of a file name, and the name in an
/// import table is spelled the way the library was built.
fn same_name(a : String, b : String) -> Bool {
  let x = string_to_utf8_bytes(a)
  let y = string_to_utf8_bytes(b)
  if x.length() != y.length() {
    return false
  }
  let mut i = 0
  while i < x.length() {
    if lower_byte(x.at(i)) != lower_byte(y.at(i)) {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Does `name` start with `prefix`, whatever the case of the letters?
fn starts_with_ignoring_case(name : String, prefix : String) -> Bool {
  let n = string_to_utf8_bytes(name)
  let p = string_to_utf8_bytes(prefix)
  if n.length() < p.length() {
    return false
  }
  let mut i = 0
  while i < p.length() {
    if lower_byte(n.at(i)) != p.at(i) {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// The byte in lower case, for the letters of the Latin alphabet.
fn lower_byte(b : Byte) -> Byte {
  if b >= b'A' && b <= b'Z' {
    (b.to_int() + 32).to_byte()
  } else {
    b
  }
}
