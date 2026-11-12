// The `--GUI` front end.
//
// LunaPack and LunaPack Studio are one product, not two packages. There is
// one version, one tag and one GitHub release. Studio is an optional asset of
// that release; it is not published to Mooncakes and has no version of its
// own.
//
// `lunapack --GUI` finds Studio locally, downloads it from the very same
// release with a progress bar when it is missing, and starts it with the
// command line the user already typed. The flags are *forwarded*, not acted
// on: the window opens with the input/output/files fields already filled in.

///|
/// The version of this CLI. `studio_wbtest.mbt` reads moon.mod and refuses to
/// let the two drift apart, because the download URL is built from this.
pub const CLI_VERSION : String = "0.1.21"

///|
fn is_gui_flag(a : String) -> Bool {
  a == "--GUI" ||
  a == "--gui" ||
  a == "-GUI" ||
  a == "-gui" ||
  a == "--GUI=true" ||
  a == "--gui=true" ||
  a == "-GUI=true" ||
  a == "-gui=true" ||
  a == "--studio" ||
  a == "--Studio" ||
  a == "--studio=true" ||
  a == "--Studio=true"
}

///|
/// Is the GUI being asked for? The switch may sit anywhere on the command
/// line, so `lunapack --GUI ...` and `lunapack ... --GUI` both work.
pub fn wants_gui(argv : ArrayView[String]) -> Bool {
  for a in argv {
    if is_gui_flag(a) {
      return true
    }
  }
  false
}

///|
/// The command line with the GUI switch taken out, in its original order.
fn without_gui_flags(argv : ArrayView[String]) -> Array[String] {
  let out : Array[String] = []
  for a in argv {
    if !is_gui_flag(a) {
      out.push(a)
    }
  }
  out
}

///|
/// The path of this executable, in the form the GUI can pass back to the
/// `bundle` subprocess. The image path is asked of the operating system, not
/// taken from argv[0], for the same reason the self-extracting launcher does.
fn self_exe() -> String {
  match current_exe_path() {
    Some(p) => norm_sep(p)
    None => norm_sep(@env.args()[0])
  }
}

///|
/// What Studio receives. Everything the user typed is kept, and `--cli` is
/// added so the window always knows which LunaPack to drive - even when it
/// was downloaded into a cache folder far away from the checkout.
fn studio_arguments(argv : ArrayView[String]) -> Array[String] {
  let out = without_gui_flags(argv)
  let mut has_cli = false
  for a in out {
    if a == "--cli" || a.has_prefix("--cli=") {
      has_cli = true
    }
  }
  if !has_cli {
    out.push("--cli=" + self_exe())
  }
  out
}

///|
fn studio_exe_name() -> String {
  if host_platform() == "windows" {
    "lunapack-studio.exe"
  } else {
    "lunapack-studio"
  }
}

///|
/// The architecture part of the asset name. `default_arch` reads environment
/// variables that POSIX shells do not always export; a download that guesses
/// wrong is worse than one that tries the common architecture, because the
/// URL can always be overridden.
fn studio_arch() -> String {
  let a = default_arch()
  if a == "unknown" {
    "x86_64"
  } else {
    a
  }
}

///|
/// The name of the Studio asset in this version's release.
pub fn studio_asset_name() -> String {
  "lunapack-studio-" + host_platform() + "-" + studio_arch() + ".zip"
}

///|
/// Where Studio comes from. A mirror or an air-gapped install can override
/// the whole URL; the default is the release that carries this CLI.
pub fn studio_release_url() -> String {
  let fallback = "https://github.com/riantr/LunaPack/releases/download/v" +
    CLI_VERSION +
    "/" +
    studio_asset_name()
  match @env.get_env_var("LUNAPACK_STUDIO_URL") {
    Some(u) => if u == "" { fallback } else { u }
    None => fallback
  }
}

///|
/// Where a downloaded Studio lives. The directory is versioned, so a newer
/// CLI does not silently start an older window.
pub fn studio_dir() -> String {
  let home = env_or("LUNAPACK_STUDIO_HOME")
  if home != "" {
    return norm_sep(home) + "/" + CLI_VERSION
  }
  let appdata = env_or("LOCALAPPDATA")
  if appdata != "" {
    return norm_sep(appdata) + "/LunaPack/Studio/" + CLI_VERSION
  }
  let xdg = env_or("XDG_CACHE_HOME")
  if xdg != "" {
    return norm_sep(xdg) + "/lunapack/studio/" + CLI_VERSION
  }
  let user = env_or("HOME")
  if user != "" {
    return norm_sep(user) + "/.cache/lunapack/studio/" + CLI_VERSION
  }
  ".lunapack/studio/" + CLI_VERSION
}

///|
/// Places a Studio executable may already be, most specific first. The
/// dev-checkout entries mean a build straight from the source tree works
/// without any download at all.
fn studio_candidates() -> Array[String] {
  let name = studio_exe_name()
  let out : Array[String] = []
  let explicit = env_or("LUNAPACK_STUDIO")
  if explicit != "" {
    let p = norm_sep(explicit)
    out.push(p)
    out.push(p + "/" + name)
  }
  let dir = dirname(self_exe())
  if dir != "" {
    out.push(dir + "/" + name)
    out.push(dir + "/studio/" + name)
    out.push(dir + "/dist/lunapack-studio/" + name)
    // A build straight from the source tree: the CLI sits in
    // LunaPack/_build/native/<profile>/build, while the Studio workspace is a
    // sibling of the LunaPack checkout. Walking up five levels lands on the
    // directory that holds both projects.
    out.push(dir + "/../../../../../LunaPackGUI/dist/lunapack-studio/" + name)
    out.push(dir + "/../../../../dist/lunapack-studio/" + name)
  }
  let cache = studio_dir()
  out.push(cache + "/" + name)
  // proton_cli packages the window inside a folder of the same name.
  out.push(cache + "/lunapack-studio/" + name)
  out
}

///|
async fn find_studio() -> String? {
  for p in studio_candidates() {
    if @fs.exists(p) && @fs.kind(p, follow_symlink=true) != Directory {
      return Some(p)
    }
  }
  None
}

///|
/// Turn a redirect target into an absolute URL. GitHub answers a release
/// asset request with an absolute signed URL, but a mirror need not.
fn absolute_url(base : String, loc : String) -> String raise {
  if loc.has_prefix("http://") || loc.has_prefix("https://") {
    return loc
  }
  let scheme = match base.find("://") {
    Some(i) => i + 3
    None => fail("the Studio download URL has no scheme")
  }
  let rest = base[scheme:].to_owned()
  let authority = match rest.find("/") {
    Some(i) => rest[:i].to_owned()
    None => rest
  }
  let prefix = base[:scheme].to_owned() + authority
  if loc.has_prefix("/") {
    return prefix + loc
  }
  let path = rest[authority.length():].to_owned()
  let slash = path.rev_find("/")
  let directory = match slash {
    Some(i) => path[:i + 1].to_owned()
    None => "/"
  }
  prefix + directory + loc
}

///|
fn decimal(text : String) -> Int64 {
  let mut n = 0L
  for i = 0; i < text.length(); i = i + 1 {
    // `i` is bounded by `text.length()`, so `text[i]` is always a valid index.
    let c = text[i].to_int() - 48
    if c < 0 || c > 9 {
      return n
    }
    n = n * 10L + c.to_int64()
  }
  n
}

///|
fn header_value(header : @http.ResponseHeader, key : String) -> String {
  match header.headers.get(key) {
    Some(v) => v
    None => ""
  }
}

///|
/// A loopback server is a local mirror or a test fixture. Sending those
/// requests out through a corporate proxy either fails or loops back into
/// the wrong machine, so they always go direct.
pub fn is_loopback_url(url : String) -> Bool {
  let rest = match url.find("://") {
    Some(i) => url[i + 3:].to_owned()
    None => url
  }
  let authority = match rest.find("/") {
    Some(i) => rest[:i].to_owned()
    None => rest
  }
  let host = match authority.rev_find("@") {
    Some(i) => authority[i + 1:].to_owned()
    None => authority
  }
  // Strip the port and brackets of an IPv6 literal.
  let bare = if host.has_prefix("[") {
    match host.find("]") {
      Some(i) => host[1:i].to_owned()
      None => host
    }
  } else {
    match host.find(":") {
      Some(i) => host[:i].to_owned()
      None => host
    }
  }
  let bare = bare.to_lower()
  bare == "localhost" ||
  bare == "127.0.0.1" ||
  bare == "::1" ||
  bare.has_suffix(".localhost")
}

///|
/// Does `NO_PROXY` name this host? The value is a comma-separated list of
/// host names or suffixes; the wildcard "*" disables the proxy entirely.
fn proxy_bypassed(url : String) -> Bool {
  if is_loopback_url(url) {
    return true
  }
  let no_proxy = env_or("NO_PROXY")
  let no_proxy = if no_proxy == "" { env_or("no_proxy") } else { no_proxy }
  if no_proxy == "*" {
    return true
  }
  let rest = match url.find("://") {
    Some(i) => url[i + 3:].to_owned()
    None => url
  }
  let authority = match rest.find("/") {
    Some(i) => rest[:i].to_owned()
    None => rest
  }
  let host_part = match authority.find(":") {
    Some(i) => authority[:i].to_owned()
    None => authority
  }
  let host = host_part.to_lower()
  for rule in no_proxy.split(",") {
    let r = rule.trim().to_owned().to_lower()
    if r == "" {
      continue
    }
    let bare : String = if r.has_prefix(".") { r[1:].to_owned() } else { r }
    if host == bare || host.has_suffix("." + bare) {
      return true
    }
  }
  false
}

///|
/// A proxy, when the machine has one. GitHub is reached over TLS through a
/// CONNECT tunnel; a proxy that cannot be used simply means a direct try.
async fn download_proxy(url : String) -> @http.ClientConnection? {
  if proxy_bypassed(url) {
    return None
  }
  let proxy = env_or("HTTPS_PROXY")
  let proxy = if proxy == "" { env_or("https_proxy") } else { proxy }
  let proxy = if proxy == "" { env_or("HTTP_PROXY") } else { proxy }
  let proxy = if proxy == "" { env_or("http_proxy") } else { proxy }
  if proxy == "" {
    return None
  }
  Some(@http.ClientConnection::ClientConnection(proxy)) catch {
    _ => None
  }
}

///|
/// GET `url`, following a release redirect. The connection is returned with
/// the body still unread so the caller can count the bytes as they arrive.
async fn open_download(
  url : String,
) -> (@http.ResponseHeader, @http.ClientConnection) {
  let mut current = url
  let mut hops = 0
  while hops < 6 {
    let proxy = download_proxy(current)
    let (header, conn) = @http.get(current, proxy?)
    let code = header.code
    if code >= 300 && code < 400 {
      let location = header_value(header, "location")
      conn.skip_response_body()
      conn.close()
      if location == "" {
        fail("the Studio download redirected without a Location header")
      }
      current = absolute_url(current, location)
      hops = hops + 1
      continue
    }
    if code != 200 {
      conn.close()
      fail(
        "the Studio download returned HTTP " +
        code.to_string() +
        " for " +
        current,
      )
    }
    return (header, conn)
  }
  fail("too many redirects while downloading LunaPack Studio")
}

///|
/// `println` goes through a buffered stream that is flushed when the process
/// ends, while the progress bar writes straight to stdout. Mixing the two
/// would print every message *after* the bar, so all of this front end's
/// output uses the same stream.
async fn say(text : String) -> Unit {
  let newline = if host_platform() == "windows" { "\r\n" } else { "\n" }
  @stdio.stdout.write(@utf8.encode(text + newline))
}

///|
/// The progress line, always the same width so `\r` overwrites it cleanly.
fn download_line(done : Int64, total : Int64) -> String {
  if total > 0L {
    let p = percent_done(done, total)
    "  [" +
    progress_bar(p, 24) +
    "]  " +
    p.to_string() +
    "%  " +
    megabytes_text(done) +
    "/" +
    megabytes_text(total) +
    " MB"
  } else {
    "  " + megabytes_text(done) + " MB downloaded"
  }
}

///|
async fn show_download_progress(done : Int64, total : Int64) -> Unit {
  @stdio.stdout.write(
    @utf8.encode("\r" + fit_line(download_line(done, total), 72)),
  )
}

///|
/// Stream `url` into `path`, drawing the progress bar on stdout.
async fn download_to(url : String, path : String) -> Unit {
  ensure_parent_dir(path)
  let (header, conn) = open_download(url)
  let total = decimal(header_value(header, "content-length"))
  let file = @fs.open(path, mode=WriteOnly, create_mode=CreateOrTruncate)
  let mut done = 0L
  let mut last = -1L
  show_download_progress(done, total)
  let mut chunk = conn.read()
  while chunk is Some(bytes) {
    file.write(bytes)
    done = done + bytes.length().to_int64()
    // A bar per network packet would spend more time writing the console
    // than writing the file.
    if done - last >= 262144L || (total > 0L && done >= total) {
      show_download_progress(done, total)
      last = done
    }
    chunk = conn.read()
  }
  show_download_progress(done, total)
  @stdio.stdout.write(
    @utf8.encode(
      "\r" + fit_line("  Downloaded " + megabytes_text(done) + " MB", 72) + "\n",
    ),
  )
  conn.close()
  file.close()
  if done == 0L {
    @fs.remove(path, allow_missing=true)
    fail("the Studio download was empty")
  }
}

///|
/// Download and unpack Studio, then report the executable that appeared.
async fn install_studio(url : String) -> String {
  let dir = studio_dir()
  @fs.mkdir(dir, recursive=true, allow_exist=true)
  let archive = dir + "/studio.zip"
  download_to(url, archive)
  say("Extracting LunaPack Studio into " + dir)
  let data = @fs.read_binary(archive)
  extract_zip(data, dir)
  @fs.remove(archive, allow_missing=true)
  match find_studio() {
    Some(p) => p
    None => fail("the Studio archive did not contain " + studio_exe_name())
  }
}

///|
/// Start the window.
///
/// The child's stdout/stderr are deliberately left inherited. Redirecting
/// them into a log would keep `lunapack --GUI | ...` from blocking on a pipe,
/// but the `@process` output API is not stable across MoonBit toolchains:
/// older ones expose `redirect_to_file() -> &ProcessOutput` (a trait object),
/// while newer ones return `SharedProcessOutput` and expect a `ProcessOutput`
/// enum variant in `spawn_orphan`. LunaPack is published as source and is
/// built with whatever toolchain the user has, so no `stdout=`/`stderr=`
/// argument can be written that compiles on every generation. Portability
/// wins here: Studio is a windowed application and writes nothing to the
/// console in normal use. When stdout is a pipe, the window holds it until
/// it is closed.
async fn spawn_studio(exe : String, args : Array[String]) -> Unit {
  ignore(
    @process.spawn_orphan(exe, args, cwd=dirname(exe), no_console_window=true),
  )
}

///|
/// Start Studio with the command line that was given to the CLI.
pub async fn launch_studio(argv : ArrayView[String]) -> Unit {
  if !is_native_target() {
    say("error: --GUI needs the native LunaPack executable.")
    say(
      "       The wasm/moonx build cannot open a window; use the native release binary.",
    )
    say("       Studio asset: " + studio_release_url())
    exit_with(1)
    return
  }
  let args = studio_arguments(argv)
  let exe = match find_studio() {
    Some(p) => p
    None => {
      let url = studio_release_url()
      say("LunaPack Studio " + CLI_VERSION + " is not installed yet.")
      say("Downloading " + url)
      let installed = install_studio(url) catch {
        err => {
          say("error: cannot install LunaPack Studio: " + err.to_string())
          say(
            "       Set LUNAPACK_STUDIO to a local build, or LUNAPACK_STUDIO_URL to a mirror.",
          )
          exit_with(1)
          ""
        }
      }
      if installed == "" {
        return
      }
      installed
    }
  }
  say("Starting LunaPack Studio: " + exe)
  let started = try {
    spawn_studio(exe, args)
    true
  } catch {
    err => {
      say("error: cannot start LunaPack Studio: " + err.to_string())
      exit_with(1)
      false
    }
  }
  if !started {
    return
  }
  say("LunaPack Studio started. Close the window to finish.")
}
