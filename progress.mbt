// The progress line of a bundle that is unpacking itself.
//
// Everything here is a plain function of numbers, so that what the bar says
// can be checked without a console: what is left is the writing, which is one
// call in the launcher.

///|
/// The fraction of the work that is done, in whole percent.
///
/// A total of zero is "done": there is nothing left to do, and a bar that
/// says 0% would sit there for ever.
fn percent_done(done : Int64, total : Int64) -> Int32 {
  if total <= 0L {
    return 100
  }
  if done <= 0L {
    return 0
  }
  let p = done * 100L / total
  if p > 100L {
    return 100
  }
  p.to_int()
}

///|
/// A count of bytes as megabytes with one decimal, e.g. "44.2".
fn megabytes_text(bytes : Int64) -> String {
  if bytes <= 0L {
    return "0.0"
  }
  // Tenths of a megabyte, rounded: half a megabyte is 524288 bytes.
  let tenths = (bytes * 10L + 524288L) / 1048576L
  (tenths / 10L).to_string() + "." + (tenths % 10L).to_string()
}

///|
/// The bar itself: `width` cells, `#` for the part that is done and `-` for
/// the part that is not.
fn progress_bar(percent : Int32, width : Int32) -> String {
  if width <= 0 {
    return ""
  }
  let p = if percent < 0 { 0 } else if percent > 100 { 100 } else { percent }
  let filled = (p.to_int64() * width.to_int64() / 100L).to_int()
  let mut out = ""
  let mut i = 0
  while i < width {
    out = out + (if i < filled { "#" } else { "-" })
    i = i + 1
  }
  out
}

///|
/// Would this text survive a console that does not read UTF-8?
///
/// The file names of a package are whatever the packer put in it, and a code
/// page that cannot show them would turn the bar into noise. A name that is
/// not plain ASCII is therefore left out of the line rather than guessed at.
fn is_ascii(text : String) -> Bool {
  let mut i = 0
  while i < text.length() {
    if text[i].to_int() > 127 {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// The body of one progress line, without the carriage return.
fn progress_line(
  done_files : Int32,
  total_files : Int32,
  done_bytes : Int64,
  total_bytes : Int64,
  current : String,
  width : Int32,
) -> String {
  let percent = percent_done(done_bytes, total_bytes)
  let name = if current != "" && is_ascii(current) {
    "  " + current
  } else {
    ""
  }
  "[" +
  progress_bar(percent, width) +
  "] " +
  percent.to_string() +
  "%  " +
  done_files.to_string() +
  "/" +
  total_files.to_string() +
  " files  " +
  megabytes_text(done_bytes) +
  "/" +
  megabytes_text(total_bytes) +
  " MB" +
  name
}

///|
/// `body`, cut or padded to exactly `width` characters.
///
/// The line is rewritten in place with a carriage return, so it has to be the
/// same length every time: a shorter line would leave the tail of the one
/// before it on the screen.
fn fit_line(body : String, width : Int32) -> String {
  if width <= 0 {
    return ""
  }
  let w = width
  if body.length() > w {
    return body[0:w].to_owned()
  }
  let mut out = body
  while out.length() < w {
    out = out + " "
  }
  out
}

///|
/// The number of bytes the package carries, which is what the bar counts.
fn total_bytes_of(entries : Array[Entry]) -> Int64 {
  let mut total = 0L
  for e in entries {
    total = total + e.size
  }
  total
}
