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
    "runtime" => "Choose the lpvirt.dll runtime image"
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
/// A forwarded `--registry` names a file; the editor wants its contents. An
/// inline JSON value is left alone, so a caller that already has the text can
/// still prefill the field.
async fn registry_field_value(value : String) -> String {
  if value == "" {
    return ""
  }
  if @fs.exists(value) {
    @fs.read_file(value).text() catch {
      _ => value
    }
  } else {
    value
  }
}

///|
/// The CLI forwards its own command line when it opens this window. Reading
/// argv on the native side is the only way to see it: the renderer runs inside
/// CEF and has no access to the process arguments.
async fn handle_startup(
  _request : @shared.StartupRequest,
) -> @shared.StartupReply {
  let reply = @core.parse_startup_args(@env.args())
  { ..reply, registry_json: registry_field_value(reply.registry_json), }
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
  let registry_path = if request.virtual_enabled &&
    request.registry_json.trim().to_owned() != "" {
    let path = request.output_exe + ".lunapack-registry.json"
    @fs.write_file(path, request.registry_json) catch {
      err =>
        return {
          ok: false,
          exit_code: -1,
          output: "Could not write the registry seed file: " + err.to_string(),
        }
    }
    path
  } else {
    ""
  }
  let args = @core.bundle_arguments_with_registry(request, registry_path)
  let result : @shared.ProcessReply = try {
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
  if registry_path != "" {
    @fs.remove(registry_path) catch {
      _ => ()
    }
  }
  result
}
