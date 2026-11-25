///|
using @rabbita {type Cmd, type Emit, type Html}

///|
using @html {
  a,
  button,
  div,
  hr,
  input,
  option,
  p,
  pre,
  select,
  span,
  strong,
  textarea,
}

///|
/// Everything the window shows. The backend is deliberately stateless: every
/// path and option lives here, and the Process command receives a snapshot.
#derive(Eq)
struct Model {
  input_exe : String
  output_exe : String
  cli_path : String
  launcher : String
  name : String
  version : String
  target_os : String
  arch : String
  compression : String
  virtual_enabled : Bool
  virtual_root : String
  virtual_temp : String
  registry_json : String
  runtime_image : String
  tab : String
  menu : String
  folders : Array[String]
  selected : Int32
  nodes : Array[@shared.FileNode]
  status : String
  output : String
  busy : Bool
  error : String?
}

///|
enum Msg {
  NoOp
  InputChanged(String)
  OutputChanged(String)
  CliChanged(String)
  LauncherChanged(String)
  NameChanged(String)
  VersionChanged(String)
  OsChanged(String)
  ArchChanged(String)
  CompressionChanged(String)
  VirtualEnabledChanged(Bool)
  VirtualRootChanged(String)
  VirtualTempChanged(String)
  RegistryJsonChanged(String)
  RuntimeChanged(String)
  TabChanged(String)
  MenuToggled(String)
  BrowseInput
  BrowseOutput
  BrowseCli
  BrowseLauncher
  BrowseRuntime
  AddFolder
  EditFolder
  RemoveFolder
  SelectFolder(Int32)
  Process
  ClearLog
  Startup(@shared.StartupReply)
  Picked(String, @shared.PickReply)
  Scanned(@shared.ScanReply)
  Probed(@shared.ProbeReply)
  Processed(@shared.ProcessReply)
  CommandFailed(@proton_client.ClientFailure)
}

///|
fn initial_model() -> Model {
  {
    input_exe: "",
    output_exe: "",
    cli_path: "",
    launcher: "",
    name: "myapp",
    version: "0.1.0",
    target_os: "windows",
    arch: "x86_64",
    compression: "lz4",
    virtual_enabled: false,
    virtual_root: "C:\\virt",
    virtual_temp: "",
    registry_json: "[]",
    runtime_image: "",
    tab: "files",
    menu: "",
    folders: [],
    selected: -1,
    nodes: [],
    status: "Ready",
    output: "",
    busy: false,
    error: None,
  }
}

///|
fn failure_message(error : @proton_client.ClientFailure) -> String {
  match error {
    @proton_client.BridgeUnavailable =>
      "The Proton bridge is unavailable. Start this window with proton_cli dev."
    _ => error.message()
  }
}

///|
/// Copy the array so Rabbita sees a genuinely new model after every edit.
fn append_folder(folders : Array[String], path : String) -> Array[String] {
  let out : Array[String] = []
  for folder in folders {
    out.push(folder)
  }
  out.push(path)
  out
}

///|
fn remove_folder_at(folders : Array[String], index : Int32) -> Array[String] {
  let out : Array[String] = []
  for i = 0; i < folders.length(); i = i + 1 {
    if i != index {
      out.push(folders[i])
    }
  }
  out
}

///|
fn replace_folder_at(
  folders : Array[String],
  index : Int32,
  path : String,
) -> Array[String] {
  let out : Array[String] = []
  for i = 0; i < folders.length(); i = i + 1 {
    out.push(if i == index { path } else { folders[i] })
  }
  out
}

///|
/// Fold the CLI's forwarded flags into the initial model. Empty fields mean
/// "the CLI did not say", so the defaults of a bare window are preserved.
fn apply_startup(model : Model, reply : @shared.StartupReply) -> Model {
  let folders = if reply.file_dirs.length() == 0 {
    model.folders
  } else {
    reply.file_dirs
  }
  {
    ..model,
    input_exe: if reply.input_exe == "" {
      model.input_exe
    } else {
      reply.input_exe
    },
    output_exe: if reply.output_exe == "" {
      model.output_exe
    } else {
      reply.output_exe
    },
    cli_path: if reply.cli_path == "" {
      model.cli_path
    } else {
      reply.cli_path
    },
    launcher: if reply.launcher == "" {
      model.launcher
    } else {
      reply.launcher
    },
    compression: if reply.compression == "" {
      model.compression
    } else {
      reply.compression
    },
    name: if reply.name == "" {
      model.name
    } else {
      reply.name
    },
    version: if reply.version == "" {
      model.version
    } else {
      reply.version
    },
    target_os: if reply.target_os == "" {
      model.target_os
    } else {
      reply.target_os
    },
    arch: if reply.arch == "" {
      model.arch
    } else {
      reply.arch
    },
    virtual_enabled: reply.virtual_enabled,
    virtual_root: if reply.virtual_root == "" {
      model.virtual_root
    } else {
      reply.virtual_root
    },
    virtual_temp: if reply.virtual_temp == "" {
      model.virtual_temp
    } else {
      reply.virtual_temp
    },
    registry_json: if reply.registry_json == "" {
      model.registry_json
    } else {
      reply.registry_json
    },
    runtime_image: if reply.runtime_image == "" {
      model.runtime_image
    } else {
      reply.runtime_image
    },
    folders,
    selected: if folders.length() > 0 {
      0
    } else {
      model.selected
    },
    nodes: [],
    status: if reply.has_args {
      "Command line loaded. Review the fields, then press Process."
    } else {
      model.status
    },
  }
}

///|
fn pick_cmd(
  emit : Emit[Msg],
  tag : String,
  kind : String,
  current : String,
) -> Cmd {
  @proton_rabbita.invoke(
    @shared.pick_path,
    { kind, current, },
    reply => emit(Picked(tag, reply)),
    error => emit(CommandFailed(error)),
  )
}

///|
fn scan_cmd(emit : Emit[Msg], path : String) -> Cmd {
  @proton_rabbita.invoke(
    @shared.scan_dir,
    { path, },
    reply => emit(Scanned(reply)),
    error => emit(CommandFailed(error)),
  )
}

///|
fn update(model : Model, msg : Msg, emit : Emit[Msg]) -> (Model, Cmd) {
  match msg {
    NoOp => (model, @rabbita.none)
    InputChanged(text) =>
      ({ ..model, input_exe: text, error: None, }, @rabbita.none)
    OutputChanged(text) =>
      ({ ..model, output_exe: text, error: None, }, @rabbita.none)
    CliChanged(text) => ({ ..model, cli_path: text, }, @rabbita.none)
    LauncherChanged(text) => ({ ..model, launcher: text, }, @rabbita.none)
    NameChanged(text) => ({ ..model, name: text, }, @rabbita.none)
    VersionChanged(text) => ({ ..model, version: text, }, @rabbita.none)
    OsChanged(text) => ({ ..model, target_os: text, }, @rabbita.none)
    ArchChanged(text) => ({ ..model, arch: text, }, @rabbita.none)
    CompressionChanged(text) => ({ ..model, compression: text, }, @rabbita.none)
    VirtualEnabledChanged(on) =>
      (
        {
          ..model,
          virtual_enabled: on,
          compression: if on {
            "none"
          } else {
            model.compression
          },
          error: None,
        },
        @rabbita.none,
      )
    VirtualRootChanged(text) =>
      ({ ..model, virtual_root: text, }, @rabbita.none)
    VirtualTempChanged(text) =>
      ({ ..model, virtual_temp: text, }, @rabbita.none)
    RegistryJsonChanged(text) =>
      ({ ..model, registry_json: text, }, @rabbita.none)
    RuntimeChanged(text) => ({ ..model, runtime_image: text, }, @rabbita.none)
    TabChanged(tab) => ({ ..model, tab, menu: "", }, @rabbita.none)
    MenuToggled(key) =>
      (
        { ..model, menu: if model.menu == key { "" } else { key }, },
        @rabbita.none,
      )
    BrowseInput => (model, pick_cmd(emit, "input", "input", model.input_exe))
    BrowseOutput =>
      (model, pick_cmd(emit, "output", "output", model.output_exe))
    BrowseCli => (model, pick_cmd(emit, "cli", "cli", model.cli_path))
    BrowseLauncher =>
      (model, pick_cmd(emit, "launcher", "launcher", model.launcher))
    BrowseRuntime =>
      (model, pick_cmd(emit, "runtime", "runtime", model.runtime_image))
    AddFolder => (model, pick_cmd(emit, "folder", "folder", ""))
    EditFolder =>
      if model.selected >= 0 && model.selected < model.folders.length() {
        (model, pick_cmd(emit, "edit", "edit", model.folders[model.selected]))
      } else {
        (model, @rabbita.none)
      }
    RemoveFolder =>
      if model.selected >= 0 && model.selected < model.folders.length() {
        (
          {
            ..model,
            folders: remove_folder_at(model.folders, model.selected),
            selected: -1,
            nodes: [],
          },
          @rabbita.none,
        )
      } else {
        (model, @rabbita.none)
      }
    SelectFolder(index) =>
      (
        { ..model, selected: index, nodes: [], },
        scan_cmd(emit, model.folders[index]),
      )
    ClearLog => ({ ..model, output: "", }, @rabbita.none)
    Picked(tag, reply) =>
      if reply.path == "" {
        (model, @rabbita.none)
      } else {
        match tag {
          "input" =>
            ({ ..model, input_exe: reply.path, error: None, }, @rabbita.none)
          "output" =>
            ({ ..model, output_exe: reply.path, error: None, }, @rabbita.none)
          "cli" => ({ ..model, cli_path: reply.path, }, @rabbita.none)
          "launcher" => ({ ..model, launcher: reply.path, }, @rabbita.none)
          "runtime" => ({ ..model, runtime_image: reply.path, }, @rabbita.none)
          "folder" => {
            let folders = append_folder(model.folders, reply.path)
            (
              {
                ..model,
                folders,
                selected: folders.length() - 1,
                nodes: [],
                error: None,
              },
              scan_cmd(emit, reply.path),
            )
          }
          "edit" =>
            if model.selected >= 0 && model.selected < model.folders.length() {
              (
                {
                  ..model,
                  folders: replace_folder_at(
                    model.folders,
                    model.selected,
                    reply.path,
                  ),
                  nodes: [],
                },
                scan_cmd(emit, reply.path),
              )
            } else {
              (model, @rabbita.none)
            }
          _ => (model, @rabbita.none)
        }
      }
    Scanned(reply) => ({ ..model, nodes: reply.nodes, }, @rabbita.none)
    Startup(reply) =>
      (
        apply_startup(model, reply),
        @proton_rabbita.invoke(
          @shared.probe_cli,
          { hint: "", },
          probe => emit(Probed(probe)),
          error => emit(CommandFailed(error)),
        ),
      )
    Probed(reply) => {
      let next = if reply.found && model.cli_path == "" {
        { ..model, cli_path: reply.cli_path, }
      } else {
        model
      }
      // A folder handed over on the command line is selected, so show its
      // contents in the tree instead of an empty pane.
      if next.folders.length() > 0 &&
        next.selected >= 0 &&
        next.nodes.length() == 0 {
        (next, scan_cmd(emit, next.folders[next.selected]))
      } else {
        (next, @rabbita.none)
      }
    }
    Process =>
      if model.busy {
        (model, @rabbita.none)
      } else if model.input_exe == "" || model.output_exe == "" {
        (
          {
            ..model,
            error: Some("Choose an input file and an output file first."),
          },
          @rabbita.none,
        )
      } else if model.virtual_enabled && model.launcher == "" {
        (
          {
            ..model,
            error: Some(
              "A virtual bundle needs lpvhost.exe. Choose it as the launcher on the Options tab.",
            ),
          },
          @rabbita.none,
        )
      } else {
        let request = @shared.ProcessRequest::{
          input_exe: model.input_exe,
          output_exe: model.output_exe,
          file_dirs: model.folders,
          cli_path: model.cli_path,
          launcher: model.launcher,
          compression: model.compression,
          name: model.name,
          version: model.version,
          target_os: model.target_os,
          arch: model.arch,
          virtual_enabled: model.virtual_enabled,
          virtual_root: model.virtual_root,
          virtual_temp: model.virtual_temp,
          registry_json: model.registry_json,
          runtime_image: model.runtime_image,
        }
        (
          {
            ..model,
            busy: true,
            status: "Packing...",
            output: "",
            error: None,
          },
          @proton_rabbita.invoke(
            @shared.run_pack,
            request,
            reply => emit(Processed(reply)),
            error => emit(CommandFailed(error)),
          ),
        )
      }
    Processed(reply) =>
      (
        {
          ..model,
          busy: false,
          status: if reply.ok {
            "Bundle written."
          } else {
            "Packing failed (exit " + reply.exit_code.to_string() + ")."
          },
          output: reply.output,
          error: if reply.ok {
            None
          } else {
            Some("Packing failed. See the output on the Options tab.")
          },
        },
        @rabbita.none,
      )
    CommandFailed(error) =>
      (
        { ..model, busy: false, error: Some(failure_message(error)), },
        @rabbita.none,
      )
  }
}

///|
fn menu_dropdown(emit : Emit[Msg], key : String) -> Html {
  match key {
    "file" =>
      div(class="menu-dropdown", [
        button(
          type_="button",
          class="menu-item",
          on_click=emit(BrowseInput),
          "Open input file...",
        ),
        button(
          type_="button",
          class="menu-item",
          on_click=emit(BrowseOutput),
          "Set output file...",
        ),
        button(
          type_="button",
          class="menu-item",
          on_click=emit(AddFolder),
          "Add folder...",
        ),
        hr(),
        button(
          type_="button",
          class="menu-item",
          on_click=emit(Process),
          "Process",
        ),
      ])
    "language" =>
      div(class="menu-dropdown", [
        button(
          type_="button",
          class="menu-item",
          on_click=emit(NoOp),
          "English",
        ),
      ])
    _ =>
      div(class="menu-dropdown", [
        div(class="menu-item menu-note", "LunaPack Studio 0.1.31"),
        a(
          href="https://github.com/riantr/LunaPack",
          class="menu-item",
          "LunaPack on GitHub",
        ),
      ])
  }
}

///|
fn menu_slot(
  emit : Emit[Msg],
  model : Model,
  label : String,
  key : String,
) -> Html {
  div(class="menu-slot", [
    button(
      type_="button",
      class=if model.menu == key { "menu-label is-open" } else { "menu-label" },
      on_click=emit(MenuToggled(key)),
      label,
    ),
    if model.menu == key {
      menu_dropdown(emit, key)
    } else {
      @html.nothing
    },
  ])
}

///|
fn menu_bar(emit : Emit[Msg], model : Model) -> Html {
  div(class="menubar", [
    menu_slot(emit, model, "File", "file"),
    menu_slot(emit, model, "Language", "language"),
    menu_slot(emit, model, "Help", "help"),
    span(class="menu-title", "LunaPack Studio"),
  ])
}

///|
fn path_row(
  label : String,
  value : String,
  placeholder : String,
  on_input : Emit[String],
  on_browse : Cmd,
) -> Html {
  div(class="path-row", [
    div(class="path-label", label),
    div(class="path-controls", [
      input(class="path-input", value~, placeholder~, on_input~),
      button(
        type_="button",
        class="browse-button",
        on_click=on_browse,
        "Browse...",
      ),
    ]),
  ])
}

///|
fn top_section(emit : Emit[Msg], model : Model) -> Html {
  div(class="top", [
    div(class="logo", ""),
    div(class="fields", [
      path_row(
        "Enter Input File Name:",
        model.input_exe,
        "C:\\myapp\\bin\\myapp.exe",
        emit.map(text => InputChanged(text)),
        emit(BrowseInput),
      ),
      path_row(
        "Enter Output File Name:",
        model.output_exe,
        "C:\\myapp\\myapp-bundle.exe",
        emit.map(text => OutputChanged(text)),
        emit(BrowseOutput),
      ),
    ]),
  ])
}

///|
fn banner() -> Html {
  div(class="banner", [
    div(class="banner-head", "LunaPack"),
    div(class="banner-body", [
      span(
        class="banner-text",
        "Bundle an executable and its folders into one runnable file. The " +
        "bundle unpacks itself on first start, or runs entirely in memory " +
        "when the virtual layer is on. ",
      ),
      a(
        href="https://github.com/riantr/LunaPack",
        class="banner-link",
        "More info",
      ),
    ]),
  ])
}

///|
fn tab_button(
  emit : Emit[Msg],
  label : String,
  key : String,
  active : String,
) -> Html {
  button(
    type_="button",
    class=if active == key { "tab is-active" } else { "tab" },
    on_click=emit(TabChanged(key)),
    label,
  )
}

///|
fn tab_strip(emit : Emit[Msg], model : Model) -> Html {
  div(class="tabs", [
    tab_button(emit, "Files", "files", model.tab),
    tab_button(emit, "Virtual", "virtual", model.tab),
    tab_button(emit, "Packaging", "packaging", model.tab),
    tab_button(emit, "Storage", "storage", model.tab),
    tab_button(emit, "Options", "options", model.tab),
  ])
}

///|
fn tree_panel(emit : Emit[Msg], model : Model) -> Html {
  let rows : Array[Html] = []
  rows.push(
    div(class="tree-line tree-root", [
      span(class="caret", "▾"),
      span(class="icon icon-root", ""),
      span(class="tree-text", "Virtual Box Files"),
    ]),
  )
  rows.push(
    div(class="tree-line tree-level1", [
      span(class="caret", "▾"),
      span(class="icon icon-folder", ""),
      span(class="tree-text", "%DEFAULT FOLDER%"),
    ]),
  )
  for i = 0; i < model.folders.length(); i = i + 1 {
    let folder = model.folders[i]
    let cls = if model.selected == i {
      "tree-line tree-level2 is-selected"
    } else {
      "tree-line tree-level2"
    }
    rows.push(
      div(class=cls, on_click=emit(SelectFolder(i)), [
        span(class="caret", ""),
        span(class="icon icon-folder", ""),
        span(class="tree-text", folder),
      ]),
    )
  }
  for node in model.nodes {
    rows.push(
      div(class="tree-line tree-level3", [
        span(class="caret", ""),
        span(
          class=if node.is_dir { "icon icon-folder" } else { "icon icon-file" },
          "",
        ),
        span(class="tree-text", node.name),
      ]),
    )
  }
  if model.folders.length() == 0 {
    rows.push(
      div(class="tree-empty", "No folders added yet. Use Add... to choose one."),
    )
  }
  div(class="tree", rows)
}

///|
fn setting_row(
  label : String,
  value : String,
  placeholder : String,
  on_input : Emit[String],
) -> Html {
  div(class="setting-row", [
    div(class="setting-label", label),
    input(class="setting-input", value~, placeholder~, on_input~),
  ])
}

///|
fn setting_path_row(
  label : String,
  value : String,
  placeholder : String,
  on_input : Emit[String],
  on_browse : Cmd,
) -> Html {
  div(class="setting-row", [
    div(class="setting-label", label),
    div(class="setting-controls", [
      input(class="setting-input", value~, placeholder~, on_input~),
      button(
        type_="button",
        class="browse-button",
        on_click=on_browse,
        "Browse...",
      ),
    ]),
  ])
}

///|
fn virtual_panel(emit : Emit[Msg], model : Model) -> Html {
  div(class="settings-panel", [
    div(class="setting-row", [
      div(class="setting-label", "Virtual layer"),
      select(on_change=emit.map(text => VirtualEnabledChanged(text == "on")), [
        option(
          value="off",
          selected=!model.virtual_enabled,
          "Off (unpacking bundle)",
        ),
        option(value="on", selected=model.virtual_enabled, "On (zero disk)"),
      ]),
    ]),
    setting_row(
      "Virtual root",
      model.virtual_root,
      "C:\\virt",
      emit.map(text => VirtualRootChanged(text)),
    ),
    setting_row(
      "Virtual temp",
      model.virtual_temp,
      "empty uses the runtime default",
      emit.map(text => VirtualTempChanged(text)),
    ),
    setting_path_row(
      "Runtime image",
      model.runtime_image,
      "empty uses lpvirt.dll beside the launcher",
      emit.map(text => RuntimeChanged(text)),
      emit(BrowseRuntime),
    ),
    div(class="setting-row", [
      div(class="setting-label", "Registry seeds"),
      textarea(
        class="json-input",
        value=model.registry_json,
        rows=9,
        placeholder="[]",
        on_input=emit.map(text => RegistryJsonChanged(text)),
        "",
      ),
    ]),
    p(
      class="info-text",
      "Seeds are JSON: an array of values, or an object with a \"values\" " +
      "array. Each value has root (hkcr/hkcu/hklm), key, name, kind " +
      "(sz/expand_sz/dword/binary) and value/number/data. Virtual bundles " +
      "store entries without compression and must use lpvhost.exe as the " +
      "launcher; encryption is not available in this mode.",
    ),
  ])
}

///|
fn packaging_panel(emit : Emit[Msg], model : Model) -> Html {
  div(class="settings-panel", [
    setting_row(
      "Package name",
      model.name,
      "myapp",
      emit.map(text => NameChanged(text)),
    ),
    setting_row(
      "Version",
      model.version,
      "0.1.0",
      emit.map(text => VersionChanged(text)),
    ),
    setting_row(
      "Target OS",
      model.target_os,
      "windows",
      emit.map(text => OsChanged(text)),
    ),
    setting_row(
      "Architecture",
      model.arch,
      "x86_64",
      emit.map(text => ArchChanged(text)),
    ),
  ])
}

///|
fn storage_panel(emit : Emit[Msg], model : Model) -> Html {
  div(class="settings-panel", [
    div(class="setting-row", [
      div(class="setting-label", "Compression method"),
      select(on_change=emit.map(codec => CompressionChanged(codec)), [
        option(value="lz4", selected=model.compression == "lz4", "LZ4 (fast)"),
        option(value="gzip", selected=model.compression == "gzip", "gzip"),
        option(
          value="none",
          selected=model.compression == "none",
          "none (store)",
        ),
      ]),
    ]),
    p(
      class="info-text",
      "LZ4 and gzip are both implemented in pure MoonBit. The choice is " +
      "written into the package, so unpacking does not need to guess.",
    ),
  ])
}

///|
fn options_panel(emit : Emit[Msg], model : Model) -> Html {
  div(class="settings-panel", [
    setting_path_row(
      "LunaPack CLI",
      model.cli_path,
      "../LunaPack/_build/native/release/build/LunaPack.exe",
      emit.map(text => CliChanged(text)),
      emit(BrowseCli),
    ),
    setting_path_row(
      "Launcher (optional)",
      model.launcher,
      "Leave empty to use the CLI itself",
      emit.map(text => LauncherChanged(text)),
      emit(BrowseLauncher),
    ),
    div(class="log-row", [
      div(class="setting-label", "Process output"),
      button(
        type_="button",
        class="small-button",
        on_click=emit(ClearLog),
        "Clear",
      ),
    ]),
    pre(
      class="log",
      if model.output == "" {
        "(no output yet)"
      } else {
        model.output
      },
    ),
  ])
}

///|
fn panel_body(emit : Emit[Msg], model : Model) -> Html {
  div(class="panel-body", [
    match model.tab {
      "virtual" => virtual_panel(emit, model)
      "packaging" => packaging_panel(emit, model)
      "storage" => storage_panel(emit, model)
      "options" => options_panel(emit, model)
      _ => tree_panel(emit, model)
    },
  ])
}

///|
fn actions(emit : Emit[Msg]) -> Html {
  div(class="actions", [
    button(type_="button", class="action", on_click=emit(AddFolder), "Add..."),
    button(type_="button", class="action", on_click=emit(EditFolder), "Edit"),
    button(
      type_="button",
      class="action",
      on_click=emit(RemoveFolder),
      "Remove",
    ),
    span(class="spacer", ""),
    button(
      type_="button",
      class="action",
      on_click=emit(TabChanged("storage")),
      "Files Options",
    ),
    button(
      type_="button",
      class="action",
      on_click=emit(TabChanged("virtual")),
      "Virtual Layer",
    ),
  ])
}

///|
fn notice(model : Model) -> Html {
  match model.error {
    Some(message) => div(class="notice is-error", message)
    None => div(class="notice", model.status)
  }
}

///|
fn footer(emit : Emit[Msg], model : Model) -> Html {
  div(class="footer", [
    div(class="footer-left", [
      div(class="project-line", [
        strong("Project: "),
        span(class="project-path", "LunaPack Studio - unsaved project"),
      ]),
      a(
        href="https://github.com/riantr/LunaPack",
        class="project-link",
        "The LunaPack project - https://github.com/riantr/LunaPack",
      ),
    ]),
    div(class="footer-right", [
      button(
        type_="button",
        class="process-button",
        disabled=model.busy,
        on_click=emit(Process),
        if model.busy {
          "Processing..."
        } else {
          "Process"
        },
      ),
    ]),
  ])
}

///|
fn view(emit : Emit[Msg], model : Model) -> Html {
  div(class="window", [
    menu_bar(emit, model),
    top_section(emit, model),
    banner(),
    notice(model),
    div(class="work-area", [
      tab_strip(emit, model),
      panel_body(emit, model),
      div(class="hint", "Drag files and folders to the Virtual Box Files tree"),
      actions(emit),
    ]),
    footer(emit, model),
  ])
}

///|
fn app() -> @rabbita.Val[Html] {
  let (model, emit) = @rabbita.create_state_with_init(
    init=emit => {
      (
        initial_model(),
        @proton_rabbita.invoke(
          @shared.startup_args,
          { hint: "", },
          reply => emit(Startup(reply)),
          error => emit(CommandFailed(error)),
        ),
      )
    },
    update=(model, msg, emit) => update(model, msg, emit),
  )
  model.view(current => view(emit, current))
}

///|
#warnings("-alert_unstable")
fn main {
  @rabbita.new(app).mount("app")
}
