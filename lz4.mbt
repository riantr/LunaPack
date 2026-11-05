// LZ4, implemented in pure MoonBit.
//
// The MoonBit toolchain ships no LZ4, so the block format and the frame
// format of the reference implementation are implemented here. What is
// produced is a standard .lz4 frame: the `lz4` tool decompresses it, and
// this implementation decompresses what that tool produces.
//
// A block is a sequence of
//
//   token    one byte; the literal length in the upper nibble, the match
//            length minus four in the lower one
//   length   zero or more bytes of 255 followed by the remainder, whenever
//            the length in the token has reached fifteen
//   literals the literal bytes
//   offset   two bytes, little endian; the distance back to the match
//
// The match is copied byte by byte, because the ranges may overlap.
//
// Two rules of the specification make a block self delimiting: the last five
// bytes are always literals, and the last match starts at least twelve bytes
// before the end of the block.
//
// LZ4 trades compression ratio for speed: it does no entropy coding at all,
// so it is several times faster than deflate while producing a larger
// result. That is the trade a packer makes when the payload is written once
// and read many times.

// ------------------------------------------------------------------ xxHash ---

///|
/// The primes of xxHash32.
const XH_P1 : UInt32 = 2654435761U

///|
const XH_P2 : UInt32 = 2246822519U

///|
const XH_P3 : UInt32 = 3266489917U

///|
const XH_P4 : UInt32 = 668265263U

///|
const XH_P5 : UInt32 = 374761393U

///|
/// Rotate a 32 bit word left by `n` bits.
fn xxh_rotl(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
/// One round of the xxHash accumulator.
fn xxh_round(acc : UInt32, val : UInt32) -> UInt32 {
  xxh_rotl(acc + val * XH_P2, 13) * XH_P1
}

///|
/// XXH32 of `data[start..end)`.
///
/// The LZ4 frame format uses this for the checksum of its header.
pub fn xxhash32(
  data : Bytes,
  start : Int32,
  end : Int32,
  seed : UInt32,
) -> UInt32 {
  let mut p = start
  let mut h : UInt32 = 0
  if end - start >= 16 {
    let mut v1 = seed + XH_P1 + XH_P2
    let mut v2 = seed + XH_P2
    let mut v3 = seed
    let mut v4 = seed - XH_P1
    while p + 16 <= end {
      v1 = xxh_round(v1, read_le32(data, p))
      p = p + 4
      v2 = xxh_round(v2, read_le32(data, p))
      p = p + 4
      v3 = xxh_round(v3, read_le32(data, p))
      p = p + 4
      v4 = xxh_round(v4, read_le32(data, p))
      p = p + 4
    }
    h = xxh_rotl(v1, 1) + xxh_rotl(v2, 7) + xxh_rotl(v3, 12) + xxh_rotl(v4, 18)
  } else {
    h = seed + XH_P5
  }
  h = h + UInt32::trunc_double((end - start).to_double())
  while p + 4 <= end {
    h = h + read_le32(data, p) * XH_P3
    h = xxh_rotl(h, 17) * XH_P4
    p = p + 4
  }
  while p < end {
    h = h + UInt32::trunc_double(data.at(p).to_double()) * XH_P5
    h = xxh_rotl(h, 11) * XH_P1
    p = p + 1
  }
  h = h ^ (h >> 15)
  h = h * XH_P2
  h = h ^ (h >> 13)
  h = h * XH_P3
  h ^ (h >> 16)
}

///|
/// Read a little endian 32 bit word at `pos`.
fn read_le32(data : Bytes, pos : Int32) -> UInt32 {
  data.at(pos).to_uint() |
  (data.at(pos + 1).to_uint() << 8) |
  (data.at(pos + 2).to_uint() << 16) |
  (data.at(pos + 3).to_uint() << 24)
}

// -------------------------------------------------------------- the format ---

///|
/// The magic number that starts every LZ4 frame.
pub const LZ4_MAGIC : UInt32 = 0x184D2204U

///|
/// The size of the blocks that a frame is cut into.
pub const LZ4_BLOCK_SIZE : Int32 = 4 * 1024 * 1024

///|
/// The smallest match that LZ4 encodes.
const LZ4_MIN_MATCH : Int32 = 4

///|
/// The last bytes of a block are always literals.
const LZ4_LAST_LITERALS : Int32 = 5

///|
/// The last match of a block starts at least this far before its end.
const LZ4_MF_LIMIT : Int32 = 12

///|
/// The number of entries of the match finder.
const LZ4_HASH_SIZE : Int32 = 1 << 16

///|
/// The largest distance a match may span.
const LZ4_MAX_DISTANCE : Int32 = 65535

///|
/// The position of a candidate match, taken from its first four bytes.
fn lz4_hash(v : UInt32) -> Int32 {
  ((v * 2654435761U) >> 16).reinterpret_as_int()
}

// ---------------------------------------------------------- the block format ---

///|
/// Write one sequence into `out` at `op`.
///
/// `match_code` is the match length minus four, or -1 for the last sequence
/// of a block, which carries literals only.
fn lz4_write_sequence(
  out : FixedArray[Byte],
  op : Int32,
  src : Bytes,
  from : Int32,
  lit_len : Int32,
  distance : Int32,
  match_code : Int32,
) -> Int32 {
  let ll = if lit_len >= 15 { 15 } else { lit_len }
  let ml = if match_code < 0 {
    0
  } else if match_code >= 15 {
    15
  } else {
    match_code
  }
  out[op] = ((ll << 4) | ml).to_byte()
  let mut p = op + 1
  if lit_len >= 15 {
    let mut rest = lit_len - 15
    while rest >= 255 {
      out[p] = 255U.to_byte()
      p = p + 1
      rest = rest - 255
    }
    out[p] = rest.to_byte()
    p = p + 1
  }
  let mut i = 0
  while i < lit_len {
    out[p] = src.at(from + i)
    p = p + 1
    i = i + 1
  }
  if match_code >= 0 {
    // The distance back to the match.
    out[p] = (distance & 0xFF).to_byte()
    out[p + 1] = ((distance >> 8) & 0xFF).to_byte()
    p = p + 2
    if match_code >= 15 {
      let mut rest = match_code - 15
      while rest >= 255 {
        out[p] = 255U.to_byte()
        p = p + 1
        rest = rest - 255
      }
      out[p] = rest.to_byte()
      p = p + 1
    }
  }
  p
}

///|
/// Compress `src[start..end)` into one LZ4 block.
///
/// The returned buffer is larger than the block, because the worst case of
/// the format needs a little more room than the input; the number of bytes
/// that the block really uses is returned with it.
fn lz4_compress_block(
  src : Bytes,
  start : Int32,
  end : Int32,
) -> (FixedArray[Byte], Int32) {
  let n = end - start
  let room = n + n / 255 + 16
  let out = FixedArray::make(room, b'\x00')
  if n < LZ4_MF_LIMIT + 1 {
    // Too short for a match to be worth looking for: it is all literals.
    let used = lz4_write_sequence(out, 0, src, start, n, 0, -1)
    return (out, used)
  }
  let table = FixedArray::make(LZ4_HASH_SIZE, -1)
  let mut anchor = start
  let mut ip = start
  // A match may not start within the last twelve bytes.
  let mflimit = end - LZ4_MF_LIMIT
  // A match may not reach into the last five bytes.
  let matchlimit = end - LZ4_LAST_LITERALS
  let mut op = 0
  while ip < mflimit {
    let seq = read_le32(src, ip)
    let h = lz4_hash(seq)
    let candidate = table[h]
    table[h] = ip
    let matched = candidate >= 0 &&
      ip - candidate <= LZ4_MAX_DISTANCE &&
      read_le32(src, candidate) == seq
    if matched {
      let mut m = ip
      let mut r = candidate
      // The match may reach back over the literals that came before it.
      while m > anchor && r > start && src.at(m - 1) == src.at(r - 1) {
        m = m - 1
        r = r - 1
      }
      let lit_len = m - anchor
      let mut match_len = LZ4_MIN_MATCH
      while m + match_len < matchlimit &&
            src.at(m + match_len) == src.at(r + match_len) {
        match_len = match_len + 1
      }
      op = lz4_write_sequence(
        out,
        op,
        src,
        anchor,
        lit_len,
        m - r,
        match_len - LZ4_MIN_MATCH,
      )
      ip = m + match_len
      anchor = ip
      // The position two bytes back is a candidate as well. It may not be
      // the position itself, because the entry that is looked up next would
      // then be the block matching itself.
      if ip - 2 > anchor {
        table[lz4_hash(read_le32(src, ip - 2))] = ip - 2
      }
    } else {
      ip = ip + 1
    }
  }
  // The last literals close the block.
  let used = lz4_write_sequence(out, op, src, anchor, end - anchor, 0, -1)
  (out, used)
}

///|
/// Decompress the LZ4 block in `src[start..end)` into `out` at `out_len`.
///
/// Returns the number of bytes that were written, or `None` when the block
/// is malformed. A block that comes from a package is not trusted: a length
/// that runs past the input, a match that points before the output, or an
/// output that would run past the buffer must be reported as damage rather
/// than read or written out of bounds.
fn lz4_decompress_block(
  src : Bytes,
  start : Int32,
  end : Int32,
  out : FixedArray[Byte],
  out_len : Int32,
) -> Int32? {
  if start < 0 || end > src.length() || start > end {
    return None
  }
  if out_len < 0 || out_len > out.length() {
    return None
  }
  let mut ip = start
  let mut op = out_len
  while ip < end {
    let token = src.at(ip).to_int()
    ip = ip + 1
    let mut lit_len = token >> 4
    if lit_len == 15 {
      let mut more = true
      while more {
        if ip >= end {
          return None
        }
        let b = src.at(ip).to_int()
        ip = ip + 1
        // The literals have to fit in the bytes left in this block. Bounding
        // the sum as it grows also keeps it from wrapping on a 32-bit target.
        if lit_len > end - ip - b {
          return None
        }
        lit_len = lit_len + b
        more = b == 255
      }
    }
    if lit_len > end - ip || lit_len > out.length() - op {
      return None
    }
    let mut i = 0
    while i < lit_len {
      out[op] = src.at(ip)
      op = op + 1
      ip = ip + 1
      i = i + 1
    }
    if ip >= end {
      // The last sequence of a block carries literals only.
      break
    }
    if ip + 2 > end {
      return None
    }
    let distance = src.at(ip).to_int() | (src.at(ip + 1).to_int() << 8)
    ip = ip + 2
    // A match must point backwards into bytes that were already written.
    if distance < 1 || distance > op {
      return None
    }
    let mut match_len = token & 15
    if match_len == 15 {
      let mut more = true
      while more {
        if ip >= end {
          return None
        }
        let b = src.at(ip).to_int()
        ip = ip + 1
        if match_len > out.length() - op - LZ4_MIN_MATCH - b {
          return None
        }
        match_len = match_len + b
        more = b == 255
      }
    }
    match_len = match_len + LZ4_MIN_MATCH
    if match_len > out.length() - op {
      return None
    }
    // The match is copied byte by byte, because the ranges may overlap.
    let mut m = op - distance
    let mut k = 0
    while k < match_len {
      out[op] = out[m]
      op = op + 1
      m = m + 1
      k = k + 1
    }
  }
  Some(op)
}

// ----------------------------------------------------------- the frame format ---

///|
/// The flags of a frame: version one, independent blocks and no checksum.
const LZ4_FLG : UInt32 = 0x60U

///|
/// The block size field: blocks of four megabytes.
const LZ4_BD : UInt32 = 0x70U

///|
/// Compress `data` into a standard LZ4 frame.
pub fn lz4_compress_frame(data : Bytes) -> Bytes {
  let n = data.length()
  let out = []
  // The magic number.
  out.push((LZ4_MAGIC & 0xFF).to_byte())
  out.push(((LZ4_MAGIC >> 8) & 0xFF).to_byte())
  out.push(((LZ4_MAGIC >> 16) & 0xFF).to_byte())
  out.push(((LZ4_MAGIC >> 24) & 0xFF).to_byte())
  // The flags and the block size.
  out.push(LZ4_FLG.to_byte())
  out.push(LZ4_BD.to_byte())
  // The checksum of the header: the high byte of the xxHash of the
  // descriptor, which is the flags and the block size here.
  let descriptor = Bytes::from_array([LZ4_FLG.to_byte(), LZ4_BD.to_byte()])
  let hc = (xxhash32(descriptor, 0, 2, 0U) >> 8) & 0xFFU
  out.push(hc.to_byte())
  // The blocks.
  let mut pos = 0
  while pos < n {
    let len = if n - pos < LZ4_BLOCK_SIZE { n - pos } else { LZ4_BLOCK_SIZE }
    let (block, size) = lz4_compress_block(data, pos, pos + len)
    if size < len {
      // The block is stored compressed.
      out.push((size & 0xFF).to_byte())
      out.push(((size >> 8) & 0xFF).to_byte())
      out.push(((size >> 16) & 0xFF).to_byte())
      out.push(((size >> 24) & 0xFF).to_byte())
      out.append(block.clamped_view(end=size))
    } else {
      // The block did not get smaller, so it is stored as it is.
      let raw = (len | 0x80000000) & 0xFFFFFFFF
      out.push((raw & 0xFF).to_byte())
      out.push(((raw >> 8) & 0xFF).to_byte())
      out.push(((raw >> 16) & 0xFF).to_byte())
      out.push(((raw >> 24) & 0xFF).to_byte())
      let mut i = 0
      while i < len {
        out.push(data.at(pos + i))
        i = i + 1
      }
    }
    pos = pos + len
  }
  // The end mark.
  out.push(0U.to_byte())
  out.push(0U.to_byte())
  out.push(0U.to_byte())
  out.push(0U.to_byte())
  Bytes::from_array(out[:])
}

///|
/// Decompress the LZ4 frame in `src`.
///
/// `size` is the number of bytes the frame holds once it is decompressed; the
/// frame format does not carry it, so the caller has to know it.
pub fn lz4_decompress_frame(src : Bytes, size : Int32) -> Bytes {
  if size < 0 || src.length() < 7 {
    // A frame that is broken is returned as it is, so that the checksum of
    // the entry reports the damage instead of the program stopping with an
    // error.
    return src
  }
  // Every byte of a frame stands for at most 255 bytes of output, so this is
  // the most a frame of this length can produce. A manifest that claims more
  // is not asking for a decompression, it is asking for an allocation.
  let max_output = src.length().to_int64() * 256L + 65536L
  if size.to_int64() > max_output {
    return src
  }
  let magic = read_le32(src, 0)
  if magic != LZ4_MAGIC {
    return src
  }
  let flg = src.at(4).to_uint()
  // Only version 01 is defined, and bit 1 is reserved and has to be zero.
  if ((flg >> 6) & 0x3U) != 1U || (flg & 0x02U) != 0U {
    return src
  }
  let mut p = 6
  if (flg & 0x08U) != 0U {
    // The size of the content.
    p = p + 8
  }
  if (flg & 0x01U) != 0U {
    // The identifier of the dictionary. It is bit 0, not the reserved bit 1.
    p = p + 4
  }
  // The checksum of the header.
  p = p + 1
  if p > src.length() {
    return src
  }
  let out = FixedArray::make(size, b'\x00')
  let mut written = 0
  while true {
    // Subtracting rather than adding keeps `p + n` from wrapping on a
    // 32-bit target, where a hostile length could pass the guard otherwise.
    if 4 > src.length() - p {
      return src
    }
    let header = read_le32(src, p)
    p = p + 4
    if header == 0U {
      // The end mark.
      break
    }
    let stored = (header & 0x80000000U) != 0U
    let len = (header & 0x7FFFFFFFU).reinterpret_as_int()
    if len > src.length() - p {
      return src
    }
    if stored {
      if len > out.length() - written {
        return src
      }
      let mut i = 0
      while i < len {
        out[written] = src.at(p + i)
        written = written + 1
        i = i + 1
      }
    } else {
      match lz4_decompress_block(src, p, p + len, out, written) {
        Some(n) => written = n
        None => return src
      }
    }
    p = p + len
    if (flg & 0x10U) != 0U {
      // The checksum of the block.
      if 4 > src.length() - p {
        return src
      }
      p = p + 4
    }
  }
  Bytes::from_array(out[:])
}
