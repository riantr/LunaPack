///|
/// Open the platform's own file/folder picker. The command context carries a
/// window handle; without one (headless runs) there is no dialog to show.
async fn handle_pick(
  context : @proton.CommandContext,
  request : @shared.PickRequest,
) -> @shared.PickReply {
  let title = match request.kind {
    "output" => "Choose where to write the bundle"
    "folder" | "edit" => "Choose a folder of files to bundle"
    "cli" | "launcher" => "Choose the LunaPack executable"
    _ => "Choose the application executable"
  }
  let chosen = match context.window() {
    None => None
    Some(window) =>
      match request.kind {
        "output" => window.save_file(Some(title), None)
        "folder" | "edit" => window.choose_directory(Some(title), None)
        _ => window.open_file(Some(title), None)
      }
  }
  {
    path: match chosen {
      Some(path) => path
      None => ""
    },
  }
}

///|
/// One level of the folder, so the tree shows what will actually be bundled.
async fn handle_scan(request : @shared.ScanRequest) -> @shared.ScanReply {
  let nodes : Array[@shared.FileNode] = []
  if request.path != "" {
    let names = @fs.readdir(request.path, sort=true) catch { _ => [] }
    for name in names {
      let full = request.path + "/" + name
      let is_dir = try @fs.kind(full) == @fs.FileKind::Directory catch {
        _ => false
      }
      nodes.push({ name, path: full, is_dir, })
    }
  }
  { nodes, }
}

///|
/// A discovered CLI is reported as an absolute path. A packaged app does not
/// necessarily start in this project's directory, so a relative candidate
/// would stop working as soon as the working directory changes.
async fn absolute_path(path : String) -> String {
  let resolved = @fs.realpath(path) catch { _ => "" }
  if resolved == "" {
    path
  } else {
    resolved
  }
}

///|
async fn handle_probe(_request : @shared.ProbeRequest) -> @shared.ProbeReply {
  match @env.get_env_var("LUNAPACK_CLI") {
    Some(path) =>
      if path != "" && @fs.exists(path) {
        return { cli_path: absolute_path(path), found: true, }
      }
    None => ()
  }
  for candidate in @core.cli_candidates() {
    if @fs.exists(candidate) {
      return { cli_path: absolute_path(candidate), found: true, }
    }
  }
  { cli_path: "", found: false, }
}

///|
/// The CLI forwards its own command line when it opens this window. Reading
/// argv on the native side is the only way to see it: the renderer runs inside
/// CEF and has no access to the process arguments.
async fn handle_startup(
  _request : @shared.StartupRequest,
) -> @shared.StartupReply {
  @core.parse_startup_args(@env.args())
}

///|
async fn handle_run_pack(
  request : @shared.ProcessRequest,
) -> @shared.ProcessReply {
  let cli = if request.cli_path == "" {
    @core.default_cli()
  } else {
    request.cli_path
  }
  let args = @core.bundle_arguments(request)
  try {
    let (code, captured) = @process.collect_output_merged(
      cli,
      args,
      no_console_window=true,
    )
    let output = captured.text() catch { _ => "" }
    { ok: code == 0, exit_code: code, output, }
  } catch {
    _ =>
      {
        ok: false,
        exit_code: -1,
        output: "Could not start the LunaPack CLI at " +
        cli +
        ". Set its path on the Options tab.",
      }
  }
}
