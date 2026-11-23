// A virtual bundle, run by the runtime that the bundle itself carries.
//
// A virtual package is one file: a launcher, the runtime DLL, and an archive
// holding the program and the files it reads. Starting it must map the program
// out of the archive into the process and answer its file and registry calls
// from memory, so nothing of the payload is ever written to disk.
//
// The answer to "who runs the program" is the runtime, mapped out of the same
// archive. It has to be: the thunks that answer those calls are exported from
// `lpvirt.dll`, and MoonBit can only give a function a C name inside a
// `foreign_library` package - a package that may not have a `main`. So the
// launcher is an executable that can parse a bundle and map an image, and
// every decision about the virtual layer is taken here, in the mapped image.
//
// That split is not a matter of taste. The launcher and this DLL each carry
// their own copy of the MoonBit runtime, with its own allocator, and a MoonBit
// value that crossed between them would be freed by the heap that did not
// allocate it. So nothing but two integers crosses: the base address of this
// image, and the exit code of the program inside it.
//
// `lp_run_bundle` is the whole of that conversation.

// ---------------------------------------------------------------- win32 ---

///|
/// `CreateFileW`. The bundle is read through the real kernel32, not through a
/// thunk: the runtime's own imports are never patched (see `fallback.mbt`),
/// which is what lets it read the file it lives in.
extern "C" fn bundle_exit(code : Int32) -> Unit = "ExitProcess"

// The file-reading externs live in `thunks.mbt` and take raw addresses, not
// `Bytes`. A second declaration of any of these C symbols - even with a
// different MoonBit signature - makes the test linker treat the same Win32
// entry point as two functions and stops with a symbol collision. The small
// native buffers below are the price of keeping one declaration per symbol.

///|
/// `GENERIC_READ`.
const GENERIC_READ : Int32 = 0x80000000

///|
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`.
const FILE_SHARE_BOTH : Int32 = 3

///|
const INVALID_HANDLE : Int64 = -1L

///|
/// End the process with `code`. The launcher uses this after the program has
/// ended, so the bundle's exit code is the program's own.
pub fn host_exit(code : Int32) -> Unit {
  bundle_exit(code)
}

// ------------------------------------------------------------- strings ---

///|
/// A NUL-terminated UTF-16 string, the form every `…W` call wants. MoonBit
/// strings are UTF-16 already; only the terminator has to be added.
fn utf16z(s : String) -> Bytes {
  let a = FixedArray::make((s.length() + 1) * 2, b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i * 2] = s[i].to_byte()
  }
  Bytes::from_array(a[:])
}

///|
/// A code unit of UTF-16 to a `Char`. Surrogates are passed through as
/// replacement characters: this is used for messages and entry names, and a
/// path outside the basic plane is not worth a decoder here.
fn unit_char(v : Int32) -> Char {
  match v.to_char() {
    Some(c) => c
    None => '?'
  }
}

///|
/// UTF-16, up to the first NUL, to a MoonBit string.
fn utf16_string(b : Bytes) -> String {
  let mut s = ""
  let mut i = 0
  while i + 1 < b.length() {
    let v = b[i].to_int() | (b[i + 1].to_int() << 8)
    if v == 0 {
      break
    }
    s = s + String::make(1, unit_char(v))
    i = i + 2
  }
  s
}

///|
/// The little-endian 64-bit value at `at`.
fn u64_at(b : Bytes, at : Int32) -> Int64 {
  let mut v = 0L
  let mut i = 7
  while i >= 0 {
    v = (v << 8) | b[at + i].to_int64()
    i = i - 1
  }
  v
}

///|
fn nibble_char(v : Int32) -> Char {
  let code = if v < 10 { 48 + v } else { 87 + v }
  unit_char(code)
}

///|
/// Lowercase hex of a byte array.
fn hex_of(b : Bytes) -> String {
  let mut s = ""
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    s = s + String::make(1, nibble_char(v / 16))
    s = s + String::make(1, nibble_char(v % 16))
  }
  s
}

///|
fn hex_digit(c : UInt16) -> Int32 raise {
  let v = c.to_int()
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 87
  } else if v >= 65 && v <= 70 {
    v - 55
  } else {
    fail("a REG_BINARY value may only hold hex digits")
  }
}

///|
/// Decode a hex string, the form a `REG_BINARY` value is written in.
fn hex_bytes(text : String) -> Bytes raise {
  if text.length() % 2 != 0 {
    fail("a REG_BINARY value must have an even number of hex digits")
  }
  let out = FixedArray::make(text.length() / 2, b'\x00')
  let mut i = 0
  while i < text.length() {
    let hi = hex_digit(text[i])
    let lo = hex_digit(text[i + 1])
    out[i / 2] = ((hi << 4) | lo).to_byte()
    i = i + 2
  }
  Bytes::from_array(out[:])
}

// ------------------------------------------------------------------ sha ---
//
// The manifest says what each entry hashes to. Checking it is the difference
// between "this bundle is damaged" and "this program is broken", and a mapped
// image that is one byte off faults somewhere unrelated. Windows has carried
// SHA-256 in CNG since Vista, so the hash is a system call rather than a second
// copy of the algorithm in this image.

///|
/// `BCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, pszImplementation,
/// dwFlags)`. The handle comes back through a byte array because that is the
/// one kind of buffer MoonBit can hand to C.
#borrow(out, alg, implementation)
extern "C" fn bcrypt_open_algorithm(
  out : Bytes,
  alg : Bytes,
  implementation : Bytes,
  flags : Int32,
) -> Int32 = "BCryptOpenAlgorithmProvider"

///|
#borrow(input, output)
extern "C" fn bcrypt_hash(
  alg : Int64,
  secret : Int64,
  secret_len : Int32,
  input : Bytes,
  input_len : Int32,
  output : Bytes,
  output_len : Int32,
) -> Int32 = "BCryptHash"

///|
extern "C" fn bcrypt_close_algorithm(alg : Int64, flags : Int32) -> Int32 = "BCryptCloseAlgorithmProvider"

///|
/// SHA-256 of `data`, lowercase hex; empty when the system refuses.
///
/// The algorithm handle lives for exactly one hash: a bundle has tens of
/// entries, not millions, and a handle with a life like that cannot leak.
fn sha256_hex(data : Bytes) -> String {
  let slot = Bytes::make(8, b'\x00')
  if bcrypt_open_algorithm(slot, utf16z("SHA256"), b"", 0) != 0 {
    return ""
  }
  let alg = u64_at(slot, 0)
  defer ignore(bcrypt_close_algorithm(alg, 0))
  let out = Bytes::make(32, b'\x00')
  if bcrypt_hash(alg, 0L, 0, data, data.length(), out, 32) != 0 {
    return ""
  }
  hex_of(out)
}

// -------------------------------------------------------------- reading ---

///|
/// The path this process was started from, NUL-terminated. For a virtual
/// bundle the file is the bundle: launcher, runtime and archive in one.
fn own_module_path() -> Bytes {
  let cap = 32768
  let buf = virtual_alloc(0L, cap.to_int64(), MEM_COMMIT, PAGE_READWRITE)
  if buf == 0L {
    return b""
  }
  defer ignore(virtual_free(buf, 0L, MEM_RELEASE))
  let n = real_get_module_file_name_w(0L, buf, cap / 2)
  if n <= 0 || n >= cap / 2 - 1 {
    return b""
  }
  // Keep the terminator: `read_whole` hands these bytes straight to
  // CreateFileW as a wide string.
  peek_bytes(buf, (n + 1) * 2)
}

///|
/// The whole of `path`, or `None` when it cannot be read in one piece.
///
/// A bundle is a few megabytes at most, and the archive is read as a whole
/// because every entry is a slice of it: reading it in pieces would mean
/// seeking, and the offsets in the manifest are relative to the start.
fn read_whole(path : Bytes) -> Bytes? {
  if path.length() == 0 {
    return None
  }
  let nptr = virtual_alloc(
    0L,
    path.length().to_int64(),
    MEM_COMMIT,
    PAGE_READWRITE,
  )
  if nptr == 0L {
    return None
  }
  defer ignore(virtual_free(nptr, 0L, MEM_RELEASE))
  poke_bytes(nptr, path, path.length())
  let handle = real_create_file_w(
    nptr,
    GENERIC_READ,
    FILE_SHARE_BOTH,
    0L,
    OPEN_EXISTING,
    0x80,
    0L,
  )
  if handle == INVALID_HANDLE || handle == 0L {
    return None
  }
  defer ignore(real_close_handle(handle))
  let size_slot = virtual_alloc(0L, 8L, MEM_COMMIT, PAGE_READWRITE)
  if size_slot == 0L {
    return None
  }
  defer ignore(virtual_free(size_slot, 0L, MEM_RELEASE))
  if real_get_file_size_ex(handle, size_slot) == 0 {
    return None
  }
  let size = u64_at(peek_bytes(size_slot, 8), 0)
  if size <= 0L || size > 0x40000000L {
    return None
  }
  let buf = virtual_alloc(0L, size, MEM_COMMIT, PAGE_READWRITE)
  if buf == 0L {
    return None
  }
  defer ignore(virtual_free(buf, 0L, MEM_RELEASE))
  let read_slot = virtual_alloc(0L, 8L, MEM_COMMIT, PAGE_READWRITE)
  if read_slot == 0L {
    return None
  }
  defer ignore(virtual_free(read_slot, 0L, MEM_RELEASE))
  if real_read_file(handle, buf, size.to_int(), read_slot, 0L) == 0 {
    return None
  }
  if u64_at(peek_bytes(read_slot, 8), 0) != size {
    return None
  }
  Some(peek_bytes(buf, size.to_int()))
}

///|
/// Is the 8-byte marker at `at` the package magic?
fn is_magic(b : Bytes, at : Int32) -> Bool {
  let magic = b"APPKGD02"
  if at < 0 || at + 8 > b.length() {
    return false
  }
  let mut i = 0
  while i < 8 {
    if b[at + i] != magic[i] {
      return false
    }
    i = i + 1
  }
  true
}

// -------------------------------------------------------------- archive ---

///|
/// One entry of the package, as the manifest describes it.
struct Entry {
  path : String
  offset : Int64
  stored_size : Int64
  size : Int64
  codec : String
  checksum : String
}

///|
/// One registry value of the virtual layer.
struct Seed {
  root : String
  key : String
  name : String
  kind : String
  text : String
  number : Int32
  data : String
}

///|
/// The virtual layer, as the manifest describes it.
struct Layer {
  root : String
  main : String
  cwd : String
  temp : String
  /// (virtual path, entry name)
  files : Array[(String, String)]
  registry : Array[Seed]
}

///|
/// Everything that is read out of a bundle.
struct Bundle {
  /// The whole file, so an entry is a slice of it.
  bytes : Bytes
  /// Where the archive starts inside that file: a bundle is a launcher with
  /// the archive appended, and the offsets of the manifest and of the entries
  /// count from there, not from the start of the file.
  base : Int32
  entries : Array[Entry]
  layer : Layer
}

///|
/// The entry the CLI puts the runtime in.
///
/// It is an entry like any other, which is the point: it is covered by the
/// per-entry checksum, so the launcher refuses to map a runtime that does not
/// match the one the package was built with. Entries under `@runtime/` are the
/// bundle's own machinery; the packer keeps them out of the virtual layer, so
/// the program inside never sees them among its files.
const RUNTIME_ENTRY : String = "@runtime/lpvirt.dll"

///|
fn json_str(obj : @json.Json, key : String, dflt : String) -> String {
  match obj {
    Object(o) =>
      match o.get(key) {
        Some(String(s)) => s
        Some(_) => dflt
        None => dflt
      }
    _ => dflt
  }
}

///|
fn json_num(obj : @json.Json, key : String, dflt : Int64) -> Int64 {
  match obj {
    Object(o) =>
      match o.get(key) {
        Some(Number(n, ..)) => n.to_int64()
        Some(_) => dflt
        None => dflt
      }
    _ => dflt
  }
}

///|
fn json_arr(obj : @json.Json, key : String) -> Array[@json.Json] {
  match obj {
    Object(o) =>
      match o.get(key) {
        Some(Array(a)) => a
        _ => []
      }
    _ => []
  }
}

///|
/// The offset of the last footer in `b`, or -1 when there is none.
///
/// The footer used to be the last 24 bytes of the file and it no longer is: a
/// file is signed by appending the signature after its last byte, so a signed
/// bundle ends with the signature and the footer sits in front of it. What is
/// still true is that the archive ends where its footer says it does, so the
/// search goes backwards and takes the last footer whose two numbers place an
/// archive that starts with the marker and finishes exactly at the footer.
/// Bytes after the footer are not part of the archive.
fn find_footer(b : Bytes) -> Int32 {
  let mut p = b.length() - 24
  while p >= 0 {
    if is_magic(b, p) {
      let moff = u64_at(b, p + 8).to_int()
      let mlen = u64_at(b, p + 16).to_int()
      // The manifest sits after the marker and inside the archive, and the
      // archive starts before the footer. Written as subtractions so that a
      // number near the top of the range cannot wrap around and pass.
      if moff >= 8 && mlen > 0 && moff <= p && mlen <= p - moff {
        let base = p - moff - mlen
        if is_magic(b, base) {
          return p
        }
      }
    }
    p = p - 1
  }
  -1
}

///|
/// Where the manifest sits: a footer is the magic, the offset of the manifest
/// and its length, and it closes the archive rather than the file — a signed
/// bundle carries the signature after it. A file with no such footer anywhere
/// has no archive in it, and that is a different problem from a damaged
/// archive.
fn manifest_text(bytes : Bytes) -> (Int32, String)? {
  let n = bytes.length()
  if n < 32 {
    return None
  }
  let footer = find_footer(bytes)
  if footer < 0 {
    return None
  }
  let moff = u64_at(bytes, footer + 8).to_int()
  let mlen = u64_at(bytes, footer + 16).to_int()
  // The archive is [magic][payload][manifest][footer] and it was appended to
  // the launcher, so every offset in the footer counts from the start of the
  // archive. The start is therefore known from the end: the archive is
  // exactly the part that ends with this footer.
  let base = footer - (moff + mlen)
  if base < 0 || !is_magic(bytes, base) {
    return None
  }
  Some((base, @utf8.decode_lossy(bytes[base + moff:base + moff + mlen])))
}

///|
fn layer_of(j : @json.Json) -> Layer? {
  let v = match j {
    Object(o) =>
      match o.get("virtual") {
        Some(x) => x
        None => return None
      }
    _ => return None
  }
  match v {
    Object(_) => ()
    _ => return None
  }
  let files = []
  for f in json_arr(v, "files") {
    let path = json_str(f, "path", "")
    let entry = json_str(f, "entry", "")
    if path != "" && entry != "" {
      files.push((path, entry))
    }
  }
  let registry = []
  for r in json_arr(v, "registry") {
    registry.push({
      root: json_str(r, "root", "hkcr"),
      key: json_str(r, "key", ""),
      name: json_str(r, "name", ""),
      kind: json_str(r, "kind", "REG_SZ"),
      text: json_str(r, "text", ""),
      number: json_num(r, "number", 0L).to_int(),
      data: json_str(r, "data", ""),
    })
  }
  Some({
    root: json_str(v, "root", ""),
    main: json_str(v, "main", ""),
    cwd: json_str(v, "cwd", ""),
    temp: json_str(v, "temp", ""),
    files,
    registry,
  })
}

///|
/// Parse the manifest into the entries and the layer.
fn parse_bundle(bytes : Bytes) -> Bundle raise {
  let (base, text) = match manifest_text(bytes) {
    Some(t) => t
    None => fail("this file carries no LunaPack archive")
  }
  let j = @json.parse(text) catch {
    err => fail("the manifest is not JSON: " + err.to_string())
  }
  let entries = []
  for e in json_arr(j, "entries") {
    entries.push({
      path: json_str(e, "path", ""),
      offset: json_num(e, "offset", 0L),
      stored_size: json_num(e, "stored_size", 0L),
      size: json_num(e, "size", 0L),
      codec: json_str(e, "codec", "raw"),
      checksum: json_str(e, "checksum", ""),
    })
  }
  let layer = match layer_of(j) {
    Some(l) => l
    None =>
      fail(
        "this package carries no virtual layer: it is meant to be unpacked, not started in memory",
      )
  }
  { bytes, base, entries, layer, }
}

///|
fn find_entry(b : Bundle, name : String) -> Entry? {
  for e in b.entries {
    if e.path == name {
      return Some(e)
    }
  }
  None
}

///|
/// The decoded bytes of one entry: the stored range, decompressed, and checked
/// against the checksum the manifest carries.
fn entry_bytes(b : Bundle, e : Entry) -> Bytes raise {
  let start = b.base + e.offset.to_int()
  let end = b.base + (e.offset + e.stored_size).to_int()
  if start < 0 || end < start || end > b.bytes.length() {
    fail("entry " + e.path + " points outside the bundle")
  }
  let stored = b.bytes[start:end].to_owned()
  let data = match e.codec {
    "raw" => stored
    "gzip" =>
      @gzip.decompress(stored) catch {
        err =>
          fail("entry " + e.path + " does not decompress: " + err.to_string())
      }
    other =>
      fail(
        "entry " +
        e.path +
        " uses the " +
        other +
        " codec, which this launcher cannot read",
      )
  }
  if data.length().to_int64() != e.size {
    fail(
      "entry " +
      e.path +
      " is " +
      data.length().to_string() +
      " bytes, the manifest says " +
      e.size.to_string(),
    )
  }
  let sum = sha256_hex(data)
  if sum == "" {
    fail("cannot hash entry " + e.path)
  }
  if sum != e.checksum.to_lower() {
    fail(
      "entry " + e.path + " does not match its checksum: the bundle is damaged",
    )
  }
  data
}

///|
/// The entry name of the main program: the layer lists (path, entry) pairs and
/// `main` is one of those paths.
fn main_entry_name(layer : Layer) -> String {
  for pair in layer.files {
    if pair.0 == layer.main {
      return pair.1
    }
  }
  ""
}

// ---------------------------------------------------------------- host ---

///|
/// The runtime image this bundle carries, or empty when the file is not a
/// virtual bundle.
///
/// This is the launcher's whole view of the archive. It is answered by the
/// runtime the launcher links statically, before any of the mapped runtime
/// exists - which is why it lives here rather than in the launcher: reading an
/// archive is code this package already has, and the launcher's copy of it is
/// the same code.
pub fn host_bundle_runtime_image() -> Bytes {
  let bytes = match read_whole(own_module_path()) {
    Some(b) => b
    None => return b""
  }
  let bundle = parse_bundle(bytes) catch { _ => return b"" }
  let entry = match find_entry(bundle, RUNTIME_ENTRY) {
    Some(e) => e
    None => return b""
  }
  entry_bytes(bundle, entry) catch {
    _ => return b""
  }
}

///|
/// `LUNAPACK_VERBOSE` in the environment, as "say what happened".
fn verbose_run() -> Bool {
  // `env_get` already owns the one FFI declaration for this API. A second
  // `extern "C" ... = "GetEnvironmentVariableW"` collides with it at link
  // time even when the signatures differ.
  let flag = env_get("LUNAPACK_VERBOSE")
  flag != "" && flag != "0"
}

///|
/// Say why the bundle cannot run and hand back a code that is not the
/// program's own.
fn refuse(message : String) -> Int32 {
  eprintln("lpvhost: " + message)
  1
}

///|
/// The program a virtualized parent asked this process to run, or "" when this
/// is the start of the chain.
fn child_program() -> String {
  let line = env_get("LUNAPACK_CHILD_CMD")
  if line == "" {
    return ""
  }
  let (program, _) = split_program(line)
  program
}

///|
/// The child start: the parent published its tree in a named section and named
/// the program to run.
///
/// The archive is deliberately not read here. The tree in the section is newer
/// than the archive - the parent's program may have created, changed or deleted
/// files since it was seeded - so importing is what makes the child see the
/// same filesystem rather than a fresh copy of the package.
///
/// The program comes from the tree when the parent packed it, and from disk
/// otherwise: a program the parent installed still has to run, and it still has
/// to see the files the parent virtualized.
fn run_child(program : String, verbose : Bool) -> Int32 {
  let step = lp_import_inherited_state()
  if step != 0 {
    return refuse(
      "cannot import the virtual state the parent published (step " +
      step.to_string() +
      ")",
    )
  }
  let image = match state_vfs().read_file(program) {
    Some(b) => b
    None =>
      match read_whole(utf16z(program)) {
        Some(b) => b
        None =>
          return refuse(
            "the parent asked for " +
            program +
            ", which is neither in the virtual tree nor on disk",
          )
      }
  }
  let base = host_map(image)
  if base == 0L {
    return refuse(
      "cannot map " + program + " (reason " + host_map_error().to_string() + ")",
    )
  }
  host_set_module_path(base, program)
  let patched = host_install(base)
  if verbose {
    println(
      "child        " + program + "  " + image.length().to_string() + " B",
    )
    println(
      "mapped       " + program + "  " + patched.to_string() + " IAT slots",
    )
  }
  host_run(base)
}

///|
/// The run itself: seed the tree and the hive from the archive, map the main
/// program, hook it, start it, and hand back the code it ended with.
fn run_bundle() -> Int32 {
  let verbose = verbose_run()
  let path = own_module_path()
  // Every generation of this file is its own bootstrap. A redirected child is
  // this same program, started with the program to run in its environment, so
  // recursion needs nothing beyond this line: whatever this process starts,
  // and whatever that one starts in turn, comes back through here.
  g_runtime.bootstrap_path = utf16_string(path)
  let child = child_program()
  if child != "" {
    return run_child(child, verbose)
  }
  let bytes = match read_whole(path) {
    Some(b) => b
    None => return refuse("cannot read " + utf16_string(path))
  }
  let bundle = parse_bundle(bytes) catch {
    err => return refuse(err.to_string())
  }
  if verbose {
    println(
      "bundle       " +
      utf16_string(path) +
      "  " +
      bytes.length().to_string() +
      " B",
    )
    println("virtual root " + bundle.layer.root)
    println("main         " + bundle.layer.main)
    println(
      "layer        " +
      bundle.layer.files.length().to_string() +
      " files, " +
      bundle.layer.registry.length().to_string() +
      " registry values, " +
      bundle.entries.length().to_string() +
      " entries",
    )
  }
  // Seed the tree. Every file is decoded and checked before anything runs, so a
  // damaged bundle is refused while nothing is in flight rather than after the
  // program has half started.
  host_reset()
  let mut seeded = 0
  for pair in bundle.layer.files {
    let (vpath, name) = (pair.0, pair.1)
    let e = match find_entry(bundle, name) {
      Some(x) => x
      None =>
        return refuse(
          name + " is listed in the virtual layer but is not in the package",
        )
    }
    let data = entry_bytes(bundle, e) catch {
      err => return refuse(err.to_string())
    }
    host_add_file(vpath, data)
    seeded = seeded + 1
    if verbose {
      println(
        "  file " +
        vpath +
        "  <- " +
        name +
        "  " +
        data.length().to_string() +
        " B",
      )
    }
  }
  for s in bundle.layer.registry {
    let payload = if s.kind == "REG_BINARY" {
      hex_bytes(s.data) catch {
        err => return refuse(s.key + "\\" + s.name + ": " + err.to_string())
      }
    } else {
      b""
    }
    if !host_seed_reg(s.root, s.key, s.name, s.kind, s.text, s.number, payload) {
      return refuse("cannot seed " + s.root + "\\" + s.key + "\\" + s.name)
    }
    if verbose {
      println("  reg  " + s.root + "\\" + s.key + "\\" + s.name + "  " + s.kind)
    }
  }
  if bundle.layer.cwd != "" {
    host_set_cwd(bundle.layer.cwd)
  }
  if bundle.layer.temp != "" {
    host_set_temp(bundle.layer.temp)
  }
  // The main program: mapped from its own bytes, told where it lives, hooked,
  // and started.
  let main_name = main_entry_name(bundle.layer)
  let main_entry = match find_entry(bundle, main_name) {
    Some(e) => e
    None =>
      return refuse(
        "the main program " + bundle.layer.main + " is not in the package",
      )
  }
  let image = entry_bytes(bundle, main_entry) catch {
    err => return refuse(err.to_string())
  }
  let base = host_map(image)
  if base == 0L {
    return refuse(
      "cannot map " +
      bundle.layer.main +
      " (reason " +
      host_map_error().to_string() +
      ")",
    )
  }
  host_set_module_path(base, bundle.layer.main)
  let patched = host_install(base)
  if verbose {
    println(
      "mapped       " +
      bundle.layer.main +
      "  " +
      patched.to_string() +
      " IAT slots",
    )
    println("seeded       " + seeded.to_string() + " virtual files")
    println("runtime base " + self_base().to_string())
  }
  let code = host_run(base)
  if verbose {
    println("exit         " + code.to_string())
  }
  code
}

///|
/// The base this image was mapped at, in hex, for the verbose run. Only ever
/// called from `run_bundle`, which is where the base is known.
fn self_base() -> Int64 {
  g_runtime.self_base
}

///|
/// Run the bundle this process was started from, and hand back the exit code
/// of the program inside it.
///
/// `image_base` is where the launcher mapped this DLL. Recording it is the
/// first thing that happens: without it every hook installation below would
/// look for its thunks in a module the loader has never heard of, find none,
/// and patch nothing - which looks exactly like a program that simply does not
/// use the filesystem.
#export_name("lp_run_bundle")
pub fn lp_run_bundle(image_base : Int64) -> Int32 {
  g_runtime.self_base = image_base
  run_bundle()
}
