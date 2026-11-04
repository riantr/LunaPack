///|
/// The tests of the LZ4 implementation.
///
/// The round trip is checked against data of every shape, and the header
/// checksum is checked against the value that the reference implementation
/// produces for the same flags.

///|
/// Deterministic pseudo random bytes, so the tests do not depend on the
/// random number generator of the toolchain.
fn pseudo_random(n : Int32, seed : Int32) -> Bytes {
  let out = FixedArray::make(n, b'\x00')
  let mut state = seed | 1
  let mut i = 0
  while i < n {
    state = (state * 1103515245 + 12345) & 0x7FFFFFFF
    out[i] = ((state >> 16) & 0xFF).to_byte()
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// The same bytes again and again, which is what compresses well.
fn repetitive(n : Int32) -> Bytes {
  let out = FixedArray::make(n, b'\x00')
  let mut i = 0
  while i < n {
    out[i] = (b'a'.to_int() + i % 4).to_byte()
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// A frame has to survive the round trip.
fn assert_round_trip(data : Bytes) -> Unit raise {
  let packed = @LunaPack.lz4_compress_frame(data)
  let back = @LunaPack.lz4_decompress_frame(packed, data.length())
  assert_true(back == data)
}

///|
/// An empty payload still produces a valid frame.
test "lz4 round trip of an empty payload" {
  assert_round_trip(Bytes::from_array([]))
}

///|
/// The short payloads are all literals, which is the branch that is easy to
/// get wrong.
test "lz4 round trip of short payloads" {
  for n in 0..<40 {
    assert_round_trip(pseudo_random(n, 7))
  }
}

///|
/// Repetitive data is where the matches come from.
test "lz4 round trip of repetitive data" {
  for n in [100, 1000, 10000, 100000] {
    assert_round_trip(repetitive(n))
  }
}

///|
/// Data that does not compress at all must still survive.
test "lz4 round trip of random data" {
  for n in [1000, 50000, 200000] {
    assert_round_trip(pseudo_random(n, 99))
  }
}

///|
/// A sentence that repeats has matches that reach back over the literals
/// that came before them, which is the case that is easy to get wrong.
test "lz4 round trip of a repeating sentence" {
  let mut sentence = ""
  let mut i = 0
  while i < 200 {
    sentence = sentence + "the quick brown fox jumps over the lazy dog "
    i = i + 1
  }
  assert_round_trip(@LunaPack.string_to_utf8_bytes(sentence))
}

///|
/// The same sentence with a different period, so that the matches land on
/// other offsets.
test "lz4 round trip of sentences with other periods" {
  let words = ["alpha ", "beta ", "gamma ", "delta ", "epsilon ", "zeta "]
  for w in words {
    let mut sentence = ""
    let mut i = 0
    while i < 300 {
      sentence = sentence + w
      i = i + 1
    }
    assert_round_trip(@LunaPack.string_to_utf8_bytes(sentence))
  }
}

///|
/// A payload that is bigger than one block is cut into several of them.
test "lz4 round trip across the block boundary" {
  let data = repetitive(5 * 1024 * 1024)
  let packed = @LunaPack.lz4_compress_frame(data)
  let back = @LunaPack.lz4_decompress_frame(packed, data.length())
  assert_true(back == data)
}

///|
/// The frame starts with the magic number of the format.
test "lz4 frame starts with the magic number" {
  let packed = @LunaPack.lz4_compress_frame(Bytes::from_array([b'a']))
  assert_true(packed.at(0).to_int() == 0x04)
  assert_true(packed.at(1).to_int() == 0x22)
  assert_true(packed.at(2).to_int() == 0x4D)
  assert_true(packed.at(3).to_int() == 0x18)
}

///|
/// The header of a frame carries a checksum of its own descriptor, and the
/// reference implementation puts the same byte there.
test "lz4 header checksum matches the reference implementation" {
  // The reference tool writes the flags 0x64 and the block size 0x40 for its
  // own frames, and the checksum byte 0xA7 follows them.
  let descriptor = Bytes::from_array([0x64U.to_byte(), 0x40U.to_byte()])
  let hc = (@LunaPack.xxhash32(descriptor, 0, 2, 0U) >> 8) & 0xFFU
  assert_true(hc == 0xA7U)
}

///|
/// The xxHash of the empty input is a published value.
test "xxhash32 of the empty input" {
  let empty = Bytes::from_array([])
  assert_true(@LunaPack.xxhash32(empty, 0, 0, 0U) == 0x02CC5D05U)
}
