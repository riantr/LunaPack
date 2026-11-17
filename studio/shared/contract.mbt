///|
/// One node in the virtual-files tree. Paths are absolute so the backend can
/// scan the same folder again without guessing where it lives.
#derive(ToJson, FromJson, Eq)
pub(all) struct FileNode {
  name : String
  path : String
  is_dir : Bool
}

///|
pub extend FileNode with ToJson::{to_json}

///|
pub extend FileNode with FromJson::{from_json}

///|
pub extend FileNode with Eq::{equal, not_equal}

///|
/// Which native dialog to open. `current` seeds the dialog when the platform
/// supports it. An empty reply means the user cancelled.
#derive(ToJson, FromJson, Eq)
pub(all) struct PickRequest {
  kind : String
  current : String
}

///|
pub extend PickRequest with ToJson::{to_json}

///|
pub extend PickRequest with FromJson::{from_json}

///|
pub extend PickRequest with Eq::{equal, not_equal}

///|
#derive(ToJson, FromJson, Eq)
pub(all) struct PickReply {
  path : String
}

///|
pub extend PickReply with ToJson::{to_json}

///|
pub extend PickReply with FromJson::{from_json}

///|
pub extend PickReply with Eq::{equal, not_equal}

///|
#derive(ToJson, FromJson, Eq)
pub(all) struct ScanRequest {
  path : String
}

///|
pub extend ScanRequest with ToJson::{to_json}

///|
pub extend ScanRequest with FromJson::{from_json}

///|
pub extend ScanRequest with Eq::{equal, not_equal}

///|
#derive(ToJson, FromJson, Eq)
pub(all) struct ScanReply {
  nodes : Array[FileNode]
}

///|
pub extend ScanReply with ToJson::{to_json}

///|
pub extend ScanReply with FromJson::{from_json}

///|
pub extend ScanReply with Eq::{equal, not_equal}

///|
/// Look for a LunaPack CLI beside this project so the first run already has
/// something to work with. Users can always point at another one.
#derive(ToJson, FromJson, Eq)
pub(all) struct ProbeRequest {
  hint : String
}

///|
pub extend ProbeRequest with ToJson::{to_json}

///|
pub extend ProbeRequest with FromJson::{from_json}

///|
pub extend ProbeRequest with Eq::{equal, not_equal}

///|
#derive(ToJson, FromJson, Eq)
pub(all) struct ProbeReply {
  cli_path : String
  found : Bool
}

///|
pub extend ProbeReply with ToJson::{to_json}

///|
pub extend ProbeReply with FromJson::{from_json}

///|
pub extend ProbeReply with Eq::{equal, not_equal}

///|
/// Everything the `bundle` subcommand needs. The GUI never assembles a shell
/// command of its own; these are passed as an argument array.
#derive(ToJson, FromJson, Eq)
pub(all) struct ProcessRequest {
  input_exe : String
  output_exe : String
  file_dirs : Array[String]
  cli_path : String
  launcher : String
  compression : String
  name : String
  version : String
  target_os : String
  arch : String
}

///|
pub extend ProcessRequest with ToJson::{to_json}

///|
pub extend ProcessRequest with FromJson::{from_json}

///|
pub extend ProcessRequest with Eq::{equal, not_equal}

///|
#derive(ToJson, FromJson, Eq)
pub(all) struct ProcessReply {
  ok : Bool
  exit_code : Int32
  output : String
}

///|
pub extend ProcessReply with ToJson::{to_json}

///|
pub extend ProcessReply with FromJson::{from_json}

///|
pub extend ProcessReply with Eq::{equal, not_equal}

///|
/// What the CLI put on Studio's command line. `lunapack --GUI` forwards the
/// flags the user already typed, so the window opens with those fields filled
/// in instead of showing an empty form. An empty field means "leave the
/// default alone".
#derive(ToJson, FromJson, Eq)
pub(all) struct StartupRequest {
  hint : String
}

///|
pub extend StartupRequest with ToJson::{to_json}

///|
pub extend StartupRequest with FromJson::{from_json}

///|
pub extend StartupRequest with Eq::{equal, not_equal}

///|
#derive(ToJson, FromJson, Eq)
pub(all) struct StartupReply {
  input_exe : String
  output_exe : String
  file_dirs : Array[String]
  cli_path : String
  launcher : String
  compression : String
  name : String
  version : String
  target_os : String
  arch : String
  has_args : Bool
}

///|
pub extend StartupReply with ToJson::{to_json}

///|
pub extend StartupReply with FromJson::{from_json}

///|
pub extend StartupReply with Eq::{equal, not_equal}

///|
pub let pick_path : @proton_contract.Command[PickRequest, PickReply] = @proton_contract.command(
  "pick_path",
)

///|
pub let scan_dir : @proton_contract.Command[ScanRequest, ScanReply] = @proton_contract.command(
  "scan_dir",
)

///|
pub let probe_cli : @proton_contract.Command[ProbeRequest, ProbeReply] = @proton_contract.command(
  "probe_cli",
)

///|
pub let run_pack : @proton_contract.Command[ProcessRequest, ProcessReply] = @proton_contract.command(
  "run_pack",
)

///|
pub let startup_args : @proton_contract.Command[StartupRequest, StartupReply] = @proton_contract.command(
  "startup_args",
)
