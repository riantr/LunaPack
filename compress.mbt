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
/// The factor by which a deflate stream can grow at most.
///
/// A deflate token carries at most 258 bytes of output and costs at least two
/// bits, so a stream cannot grow beyond this. The number is what bounds the
/// size a package may claim for an entry: a claim beyond it is not a size
/// that the stored bytes can back.
///
/// The encoder does not come close to it: a mebibyte of the same byte goes
/// down to 1236 bytes, which is a ratio of 848. The margin is what keeps a
/// stream that is made by hand from being refused.
const MAX_DEFLATE_EXPANSION : Int64 = 1032L

///|
/// The size of the header of a gzip stream.
///
/// The header is the fixed ten bytes of RFC 1952: the magic, the method, the
/// flags, the time, the extra flags and the system. A stream that carries any
/// of the optional fields is not one of ours, and its header is not of this
/// size.
const GZIP_HEADER_BYTES : Int32 = 10

///|
/// The size of the trailer of a gzip stream: the CRC-32 of the content and
/// its length, both little-endian.
const GZIP_TRAILER_BYTES : Int32 = 8

///|
/// Compress `data` with gzip.
///
/// The data that does not compress is not parsed for matches that are not
/// there. The encoder samples the input first and stores the entries that
/// look like noise -- images, archives, media -- the way they are. Measured
/// on the files of this repository and the release binary of it (54 files,
/// 3.5 MB), that makes the packing of the entries 21% faster (363 ms to
/// 288 ms) for 0.07% more bytes.
pub fn gzip_compress(data : Bytes) -> Bytes {
  @gzip.compress(
    data,
    strategy=@flate.Strategy::Standard(level=GZIP_LEVEL),
    fast_store=true,
  )
}

///|
/// Decompress gzip-compressed `data`.
///
/// The size of the result is not known to the caller here, so the stream is
/// read into a buffer that grows while it is read. The unpacker knows the
/// size -- the manifest carries it -- and reads the entry into a buffer of
/// that size instead.
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
/// Decompress gzip-compressed `data` into a buffer of `size` bytes.
///
/// `size` is the number of bytes the entry holds once it is decompressed. The
/// manifest carries that number, and the gzip trailer carries it as well.
///
/// The buffer is written once, into a place of exactly the right size, rather
/// than being grown while the stream is read. Measured on the files of this
/// repository and the release binary of it (54 files, 3.5 MB), the reading of
/// the entries takes 19 ms instead of 71 ms: about four times less time.
///
/// The CRC-32 of the stream is not checked here. The entry carries a MD5 and
/// a SHA-256 of its content, and the unpacker checks both of them right
/// after this call, so the check would be a third one over the same bytes.
/// The length in the trailer is checked, because it is what says how long
/// the content is.
///
/// A size that the stored bytes cannot grow into is refused: a claim is not
/// turned into an allocation. A stream that does not hold what the size says
/// it holds is returned as it is, so that the checksum of the entry reports
/// the damage instead of the program stopping with an error.
fn gzip_decompress_into(data : Bytes, size : Int32) -> Bytes {
  // The size has to be backed by the stored bytes: a deflate stream cannot
  // grow beyond the factor, so a claim beyond it is not a size that the
  // stored bytes can reach.
  let real = match gzip_entry_size(data.length(), size.to_int64()) {
    None => -1
    Some(s) => s
  }
  if real < 0 {
    return data
  }
  // The stream has to be one of ours: the fixed header, the body, the
  // trailer.
  if data.length() < GZIP_HEADER_BYTES + GZIP_TRAILER_BYTES {
    return data
  }
  // The header has to be the fixed ten bytes of RFC 1952: the magic, the
  // method, the flags. A stream with any of the optional fields in it has a
  // header that is not of this size, and its body would not start where this
  // reads it.
  if data.at(0) != b'\x1f' ||
    data.at(1) != b'\x8b' ||
    data.at(2) != b'\x08' ||
    data.at(3) != b'\x00' {
    return data
  }
  // The trailer holds the length of the content, little-endian. It is what
  // the stream says about itself, and it has to be the size that was asked
  // for.
  let trailer = data.length() - GZIP_TRAILER_BYTES
  let isize = le32_at(data, trailer + 4)
  if isize != real.reinterpret_as_uint() {
    return data
  }
  match gzip_inflate(data, GZIP_HEADER_BYTES, trailer, real) {
    Some(plain) => plain
    None => data
  }
}

///|
/// The size a gzip entry of `stored` bytes can be read into, if the entry
/// claims `claimed` bytes.
///
/// `None` when the claim is not backed by the stored bytes. A deflate stream
/// cannot grow beyond the factor, so a claim beyond it is not a size that the
/// stored bytes can reach, and a claim that does not fit in an address is not
/// a size at all.
fn gzip_entry_size(stored : Int32, claimed : Int64) -> Int32? {
  if claimed < 0L || claimed > 0x7fffffffL {
    return None
  }
  let max_output = stored.to_int64() * MAX_DEFLATE_EXPANSION
  if claimed > max_output {
    return None
  }
  Some(claimed.to_int())
}

///|
/// Read the deflate stream that `data` holds between `from` and `to` into a
/// buffer of `size` bytes.
///
/// The stream is read once, into a place of exactly the right size, rather
/// than into a buffer that grows while it is read.
///
/// `None` when the stream does not hold what the size says it holds: the
/// caller returns the bytes as they are, so that the checksum of the entry
/// reports the damage instead of the program stopping with an error.
fn gzip_inflate(data : Bytes, from : Int32, to : Int32, size : Int32) -> Bytes? {
  let buffer = Array::make(size, b'\x00')
  // One byte of room outside the buffer. The decoder has to be able to move
  // on after the last byte of the content, and a stream that holds more than
  // the size says is caught by that one byte.
  let scratch = Array::make(1, b'\x00')
  let decoder = @flate.IncrementalDecoder::IncrementalDecoder()
  let mut pos = 0
  let mut produced = 0
  let mut finished = false
  for ;; {
    if produced > size {
      break
    }
    let view = if produced < size {
      buffer.mut_view(start=produced)
    } else {
      scratch.mut_view()
    }
    // What is left of the body is a view of the same bytes, so reading it
    // copies nothing.
    let rest = data.exact_view(start=from + pos, end=to)
    let step = decoder.step(rest, view) catch { _ => return None }
    pos = pos + step.consumed
    produced = produced + step.produced
    if step.status == @flate.Done {
      finished = true
      break
    }
    if step.produced == 0 && step.consumed == 0 {
      // The decoder cannot move on: the stream does not hold what it claims.
      break
    }
  }
  if !finished || produced != size {
    return None
  }
  Some(Bytes::from_array(buffer))
}

///|
/// The four bytes at `offset` of `data`, little-endian.
fn le32_at(data : Bytes, offset : Int32) -> UInt32 {
  data.at(offset).to_uint() |
  (data.at(offset + 1).to_uint() << 8) |
  (data.at(offset + 2).to_uint() << 16) |
  (data.at(offset + 3).to_uint() << 24)
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
