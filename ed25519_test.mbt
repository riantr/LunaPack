// Tests for the Ed25519 signature.
//
// The vectors in this file were produced by an implementation that is not
// this one, so a signature that is right here is right against every other
// implementation of RFC 8032 and not only against itself.

///|
/// The bytes from `start` up to `end`, copied into a new buffer.
fn cut(data : Bytes, start : Int32, end : Int32) -> Bytes {
  let out = FixedArray::make(end - start, b'\x00')
  let mut i = start
  while i < end {
    out[i - start] = data.at(i)
    i = i + 1
  }
  Bytes::from_array(out[:])
}

///|
/// The secret key of the first vector.
fn ed_seed() -> Bytes {
  @LunaPack.hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  ).unwrap()
}

///|
/// The public key of the first vector.
fn ed_public() -> Bytes {
  @LunaPack.hex_to_bytes(
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  ).unwrap()
}

///|
/// The signature of the empty message with the first key.
fn ed_sig_empty() -> Bytes {
  @LunaPack.hex_to_bytes(
    "9ca53579530654d5c3df77089ef45eda613e2fedf670e96bedac4639504e5845" +
    "ef4b95d5793077233dd16817b2532e9c5525872a73a4ad74b759369a9e05c102",
  ).unwrap()
}

///|
/// The signature of "lunapack" with the first key.
fn ed_sig_lunapack() -> Bytes {
  @LunaPack.hex_to_bytes(
    "27ef34ea2501c3948118f9a91e0db018f9634447cfd164957d0ce84a3963852e0" +
    "fb945fc17df6fc66a8b647cd2ee37e7dd4e272ef252596cbcffe48d93fbbc02",
  ).unwrap()
}

///|
/// The signature of a longer message with the first key.
fn ed_sig_long() -> Bytes {
  @LunaPack.hex_to_bytes(
    "2fd4e6cefe0d3acb46e556deecb67499c27baa573d5b9bf1394edfb9fa8edd8ce" +
    "ce6c29f03a6b8279ea54e52eb735832a2d4079dcd379ba28b121fe365bfcb04",
  ).unwrap()
}

///|
test "the public key of a secret key matches the reference vector" {
  assert_true(@LunaPack.ed25519_public_key(ed_seed()) == ed_public())
}

///|
test "the signature of the empty message matches the reference vector" {
  assert_true(@LunaPack.ed25519_sign(ed_seed(), b"") == ed_sig_empty())
}

///|
test "the signature of a message matches the reference vector" {
  assert_true(
    @LunaPack.ed25519_sign(ed_seed(), b"lunapack") == ed_sig_lunapack(),
  )
  assert_true(
    @LunaPack.ed25519_sign(
      ed_seed(),
      b"The quick brown fox jumps over the lazy dog",
    ) ==
    ed_sig_long(),
  )
}

///|
test "the signature is the same every time" {
  assert_true(
    @LunaPack.ed25519_sign(ed_seed(), b"lunapack") ==
    @LunaPack.ed25519_sign(ed_seed(), b"lunapack"),
  )
}

///|
test "a reference signature is accepted" {
  assert_true(@LunaPack.ed25519_verify(ed_public(), b"", ed_sig_empty()))
  assert_true(
    @LunaPack.ed25519_verify(ed_public(), b"lunapack", ed_sig_lunapack()),
  )
}

///|
test "a signature of another message is refused" {
  assert_true(
    !@LunaPack.ed25519_verify(ed_public(), b"lunapack!", ed_sig_lunapack()),
  )
  assert_true(!@LunaPack.ed25519_verify(ed_public(), b"", ed_sig_lunapack()))
}

///|
test "a signature of another key is refused" {
  let other = @LunaPack.hex_to_bytes(
    "755c4cb9256ca7cdc4acfdc6cfeeda849017e5b9f9514e99191bd67e0b0d4276",
  ).unwrap()
  assert_true(!@LunaPack.ed25519_verify(other, b"lunapack", ed_sig_lunapack()))
}

///|
test "a changed signature is refused" {
  let changed = @LunaPack.hex_to_bytes(
    "28ef34ea2501c3948118f9a91e0db018f9634447cfd164957d0ce84a3963852e0" +
    "fb945fc17df6fc66a8b647cd2ee37e7dd4e272ef252596cbcffe48d93fbbc02",
  ).unwrap()
  assert_true(!@LunaPack.ed25519_verify(ed_public(), b"lunapack", changed))
}

///|
test "a signature with a scalar that is not reduced is refused" {
  // The order of the group is 2^252 + 27742317777372353535851937790883648493.
  // A scalar that is the scalar of the signature plus that order is the same
  // signature written in another way, and accepting it would make the
  // signature malleable.
  let order = @LunaPack.hex_to_bytes(
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
  ).unwrap()
  let signature = ed_sig_lunapack()
  let not_reduced = @LunaPack.bytes_concat(cut(signature, 0, 32), order)
  assert_true(!@LunaPack.ed25519_verify(ed_public(), b"lunapack", not_reduced))
}

///|
test "a signature of the wrong length is refused" {
  assert_true(
    !@LunaPack.ed25519_verify(
      ed_public(),
      b"lunapack",
      cut(ed_sig_lunapack(), 0, 63),
    ),
  )
  assert_true(
    !@LunaPack.ed25519_verify(
      cut(ed_public(), 0, 31),
      b"lunapack",
      ed_sig_lunapack(),
    ),
  )
}

///|
test "a public key that is not a point of the curve is refused" {
  let bad = @LunaPack.hex_to_bytes(
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  ).unwrap()
  assert_true(!@LunaPack.ed25519_verify(bad, b"lunapack", ed_sig_lunapack()))
}
