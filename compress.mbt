// gzip compression helpers built on moonbitlang/async/gzip.
//
// Payloads are compressed individually so that a package can mix compressed
// and stored entries (text compresses well, already-compressed binaries do
// not).

///|
/// In-memory `@io.Writer` that accumulates everything written into an array.
priv struct BufWriter {
  buf : Array[Byte]
}

///|
impl @io.Writer for BufWriter with fn write_once(self, buf, offset~, len~) {
  let mut i = 0
  while i < len {
    self.buf.push(buf[offset + i])
    i = i + 1
  }
  len
}

///|
/// Compress `data` with gzip.
pub async fn gzip_compress(data : Bytes) -> Bytes {
  let pw = BufWriter::{ buf: [], }
  let enc = @gzip.Encoder::Encoder(pw)
  enc.write(data)
  enc.end()
  Bytes::from_array(pw.buf)
}

///|
/// Decompress gzip-compressed `data`.
pub async fn gzip_decompress(data : Bytes) -> Bytes {
  // The gzip decoder consumes a reader, so the compressed bytes are fed
  // through an in-memory reader.
  let reader = @io.MemoryReader::MemoryReader(w => w.write(data))
  let dec = @gzip.Decoder::Decoder(reader)
  let out = dec.read_all()
  out.binary()
}

///|
/// Compress `data` only when that actually makes it smaller.
/// Returns the payload to store plus the codec name to record in the manifest.
pub async fn compress_if_smaller(
  data : Bytes,
  always : Bool,
) -> (Bytes, String) {
  let gz = gzip_compress(data)
  if always || gz.length() < data.length() {
    (gz, "gzip")
  } else {
    (data, "raw")
  }
}
