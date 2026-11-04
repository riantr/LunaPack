// The exit code of a process.
//
// The MoonBit runtime owns the exit of a program: `main` returns Unit and
// the toolchain decides what the process returns. A program that has to
// report a code of its own - the self-extracting bundle reports the code
// of the program it carries - has to reach for the exit of the C library.
//
// The Wasm backend has no C library to reach for, and the compiler rejects
// an `extern "C"` declaration there, so on that backend the code is
// reported on the standard error and the program ends normally.

///|
/// End the process with `code`.
#cfg(target="native")
pub fn exit_with(code : Int32) -> Unit {
  c_exit(code)
}

///|
/// End the process with `code`.
#cfg(target="wasm")
pub fn exit_with(code : Int32) -> Unit {
  if code != 0 {
    eprintln("LunaPack: the program returned " + code.to_string())
  }
}

///|
#cfg(target="native")
extern "C" fn c_exit(code : Int32) -> Unit = "exit"
