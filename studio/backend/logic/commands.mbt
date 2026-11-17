///|
/// Explicit bindings let the compiler check each implementation against its
/// shared descriptor. No code-generation step is involved.
pub fn register_commands(registrar : @proton.CommandRegistrar) -> Unit raise {
  registrar.bind(@shared.pick_path, handle_pick)
  registrar.bind(@shared.scan_dir, (_context, request) => handle_scan(request))
  registrar.bind(@shared.probe_cli, (_context, request) => handle_probe(request))
  registrar.bind(@shared.startup_args, (_context, request) => {
    handle_startup(request)
  })
  registrar.bind(@shared.run_pack, (_context, request) => {
    handle_run_pack(request)
  })
}
