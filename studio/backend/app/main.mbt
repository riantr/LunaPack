///|
async fn main {
  @proton.asset(
    "LunaPack Studio",
    "frontend/dist/index.html",
    width=920,
    height=640,
  )
  ..config(@proton.load_config())
  ..single_instance()
  ..commands(fn(registrar) raise { @logic.register_commands(registrar) })
  .run_or_abort()
}
