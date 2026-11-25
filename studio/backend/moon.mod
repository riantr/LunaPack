name = "riantr/LunaPackGUI_backend"

version = "0.1.0"

import {
  "riantr/LunaPackGUI_shared@0.1.0",
  "moonbitlang/async@0.22.5",
  "moonbit-community/proton@0.10.0",
  "moonbit-community/proton_contract@0.10.0",
  "tonyfettes/xlog@0.5.1",
}

license = "Apache-2.0"

description = "Proton backend for LunaPack Studio."

options(
  warn_list: "",
  preferred_target: "native",
  supported_targets: "+native",
)
