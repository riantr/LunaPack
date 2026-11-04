// gzip compression helpers built on moonbitlang/core/compress/gzip.
//
// Payloads are compressed individually so that a package can mix compressed
// and stored entries (text compresses well, already-compressed binaries do
// not).

///|
/// The compression level that the entries use.
///
/// Level 1 is the fastest setting of the deflate encoder, and it is also the
/// one that produces the smallest packages here: measured on an application
/// of 392 files it compresses faster, decompresses faster and yields a
/// package that is about a quarter smaller than the stream implementation
/// did.
pub const GZIP_LEVEL : Int32 = 1

///|
/// Compress `data` with gzip.
pub fn gzip_compress(data : Bytes) -> Bytes {
  @gzip.compress(data, strategy=@flate.Strategy::Standard(level=GZIP_LEVEL))
}

///|
/// Decompress gzip-compressed `data`.
///
/// A stream that cannot be decompressed is returned as it is, so that the
/// checksum of the entry reports the damage instead of the program stopping
/// with an error.
pub fn gzip_decompress(data : Bytes) -> Bytes {
  @gzip.decompress(data) catch {
    _ => data
  }
}

///|
/// Compress `data` with the method that `method` names.
///
/// The codec is one of "none", "gzip", "lz4" or "auto". "auto" keeps the
/// raw bytes when the compression would make the entry bigger, which is what
/// happens with the small files that do not compress at all.
///
/// Returns the payload to store plus the codec name to record in the
/// manifest.
pub fn compress_with(data : Bytes, codec_name : String) -> (Bytes, String) {
  if codec_name == "lz4" {
    (lz4_compress_frame(data), "lz4")
  } else if codec_name == "gzip" {
    (gzip_compress(data), "gzip")
  } else if codec_name == "none" {
    (data, "raw")
  } else {
    let gz = gzip_compress(data)
    if gz.length() < data.length() {
      (gz, "gzip")
    } else {
      (data, "raw")
    }
  }
}
