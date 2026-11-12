// Auto-download of a native launcher for the current system.
//
// A self-extracting bundle is a native LunaPack executable with the package
// archive appended: starting it notices the payload, extracts it and runs the
// bundled program - the same trick a WinRAR or 7-Zip self-extracting archive
// uses. When LunaPack itself runs as a Wasm module there is no native
// executable of its own to append, so `bundle` needs a native launcher that
// was built for the machine the bundle will run on.
//
// `lunapack --launcher` (with no file) downloads that launcher from this
// release - the one build that matches the running system - and shows
// progress while it does. The running version picks the matching launcher
// version, so the archive format the stub reads is the one the packer wrote.

///|
/// The name of the native launcher asset for the current system.
///
/// One build per platform is shipped (see .github/workflows/release.yml):
///   lunapack-linux-x86_64
///   lunapack-windows-x86_64.exe
///   lunapack-macos-aarch64
/// A bundle for the current machine needs a launcher built for it, and these
/// are the builds that exist, so the name resolves to one of them rather than
/// to a guessed architecture that would only 404.
pub fn launcher_asset_name() -> String {
  let os = host_platform()
  // Only these architectures are published; a wrong guess is a 404, while the
  // common one always resolves.
  let arch = if os == "macos" { "aarch64" } else { "x86_64" }
  let ext = if os == "windows" { ".exe" } else { "" }
  "lunapack-" + os + "-" + arch + ext
}

///|
/// Where a downloaded launcher lives. The directory is versioned, so a newer
/// CLI does not silently start an older launcher.
pub fn launcher_dir() -> String {
  let home = env_or("LUNAPACK_LAUNCHER_HOME")
  if home != "" {
    return norm_sep(home) + "/" + CLI_VERSION
  }
  let appdata = env_or("LOCALAPPDATA")
  if appdata != "" {
    return norm_sep(appdata) + "/LunaPack/Launcher/" + CLI_VERSION
  }
  let xdg = env_or("XDG_CACHE_HOME")
  if xdg != "" {
    return norm_sep(xdg) + "/lunapack/launcher/" + CLI_VERSION
  }
  let user = env_or("HOME")
  if user != "" {
    return norm_sep(user) + "/.cache/lunapack/launcher/" + CLI_VERSION
  }
  ".lunapack/launcher/" + CLI_VERSION
}

///|
/// Where the launcher comes from. A mirror or an air-gapped install can
/// override the whole URL; the default is the release that carries this CLI.
pub fn launcher_release_url() -> String {
  let fallback = "https://github.com/riantr/LunaPack/releases/download/v" +
    CLI_VERSION +
    "/" +
    launcher_asset_name()
  match @env.get_env_var("LUNAPACK_LAUNCHER_URL") {
    Some(u) => if u == "" { fallback } else { u }
    None => fallback
  }
}

///|
/// Does the value of `--launcher` ask for an automatic download rather than a
/// file? A bare `--launcher` parses to "true"; `auto`, `download`, `yes` and
/// `1` are accepted as well, so the intent is plain on any command line.
fn is_launcher_auto(spec : String) -> Bool {
  spec == "true" ||
  spec == "auto" ||
  spec == "download" ||
  spec == "yes" ||
  spec == "1"
}

///|
/// Resolve the launcher the `bundle` step should use.
///
/// An empty spec keeps the default (the running executable, or nothing under
/// Wasm, which `bundle` already handles). A path is returned as given: the
/// existence check belongs to `bundle`, so a missing file still fails there
/// with its usual message. The auto markers trigger a download.
async fn resolve_launcher(flags : Array[Flag]) -> String {
  let spec = flag_value(flags, "launcher")
  if is_launcher_auto(spec) {
    download_launcher()
  } else {
    spec
  }
}

///|
/// Download the native launcher for the current system into the cache, or hand
/// back the one already there.
///
/// The progress bar is the same one the rest of the tool draws, and a line is
/// printed before and after it so the wait is explained rather than silent.
async fn download_launcher() -> String {
  let dir = launcher_dir()
  @fs.mkdir(dir, recursive=true, allow_exist=true)
  let asset = launcher_asset_name()
  let path = dir + "/" + asset
  // A launcher downloaded before is reused: re-downloading on every `bundle`
  // would make the feature pay for the whole file each time.
  if @fs.exists(path) {
    say("launcher 已缓存 (launcher already cached): " + path)
    return path
  }
  let url = launcher_release_url()
  say("正在下载 launcher (" + asset + ") : " + url)
  download_to(url, path) catch {
    err => {
      @fs.remove(path, allow_missing=true)
      fail(
        "无法下载 launcher (cannot download launcher): " +
        err.to_string() +
        " | set LUNAPACK_LAUNCHER_URL to a mirror, or pass --launcher <a native lunapack executable>",
      )
    }
  }
  // The file is a native executable; give it the execute bit where that
  // matters, so it can be run or appended to directly.
  set_permissions(host_platform(), path, 0o755) catch {
    _ => ()
  }
  say("launcher 下载完成 (launcher downloaded): " + path)
  path
}
