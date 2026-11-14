// Scratch folders of the test suite.
//
// A test that needs a folder of its own gets one under the temporary
// directory of the system, and the folder is taken away again when the test
// is over. Without that second half every run of the suite would leave a
// pile of scratch behind: the suite makes a few hundred folders, and a
// machine that has run it a few hundred times holds tens of thousands of
// them.
//
// The whitebox tests carry a copy of these two functions: a blackbox test
// cannot see the private items of the package it tests, so the two test
// packages cannot share one.

///|
/// A folder of scratch under the temporary directory of the system.
async fn scratch_dir(prefix : String) -> String {
  @fs.tmpdir(prefix~)
}

///|
/// Take a folder of scratch away again.
///
/// The folder and everything in it are removed. A folder that is already gone
/// is not an error: what happens to the scratch once the test is over does
/// not matter to the tool.
///
/// The removal cannot be cancelled, because it runs in a `defer`: scratch
/// that is left behind because the test was cancelled is exactly the pile of
/// scratch this is here to avoid.
async fn drop_scratch(dir : String) -> Unit nocancel {
  @fs.rmdir(dir, recursive=true, allow_missing=true) catch {
    _ => ()
  }
}

///|
/// Take away the scratch a package was made in.
///
/// The package lies in the folder it was made in, so that folder is the one
/// above it.
async fn drop_package_scratch(pkg : String) -> Unit nocancel {
  drop_scratch(@LunaPack.dirname(pkg))
}

///|
/// The scratch of a test is taken away again when the test is over.
async test "a folder of scratch is taken away again" {
  let dir = scratch_dir("lunapack_scratch")
  @fs.write_text(dir + "/a.txt", "hello")
  drop_scratch(dir)
  assert_true(!@fs.exists(dir))
}

///|
/// The scratch a package was made in is taken away again with the package.
async test "the scratch of a package is taken away again" {
  let dir = scratch_dir("lunapack_scratch_pkg")
  let pkg = dir + "/test.appkg"
  @fs.write_text(dir + "/a.txt", "hello")
  drop_package_scratch(pkg)
  assert_true(!@fs.exists(dir))
}
