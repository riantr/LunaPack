// Hexadecimal helpers.
//
// The fingerprints of the package are hex, and the keys of the encryption are
// stored as hex in the manifest and in the key files.

///|
/// The hex digit of a nibble.
fn hex_char_of(n : Int32) -> Char {
  match n {
    0 => '0'
    1 => '1'
    2 => '2'
    3 => '3'
    4 => '4'
    5 => '5'
    6 => '6'
    7 => '7'
    8 => '8'
    9 => '9'
    10 => 'a'
    11 => 'b'
    12 => 'c'
    13 => 'd'
    14 => 'e'
    15 => 'f'
    _ => '0'
  }
}

///|
/// Lowercase hex of `data`.
pub fn bytes_to_hex(data : Bytes) -> String {
  let mut out = ""
  let mut i = 0
  let n = data.length()
  while i < n {
    let b = data.at(i).to_int()
    out = out +
      String::make(1, hex_char_of(b >> 4)) +
      String::make(1, hex_char_of(b & 0x0f))
    i = i + 1
  }
  out
}

///|
/// The value of a hex digit, or -1 when it is not one.
///
/// A `String` yields a code unit when it is indexed, and the hex digits are
/// all in the ASCII range, so the code unit is compared by its number.
fn hex_value(code : Int32) -> Int32 {
  match code {
    48 => 0
    49 => 1
    50 => 2
    51 => 3
    52 => 4
    53 => 5
    54 => 6
    55 => 7
    56 => 8
    57 => 9
    97 => 10
    98 => 11
    99 => 12
    100 => 13
    101 => 14
    102 => 15
    65 => 10
    66 => 11
    67 => 12
    68 => 13
    69 => 14
    70 => 15
    _ => -1
  }
}

///|
/// Decode a hex string.
///
/// Returns None when the text is not a hex string of even length.
pub fn hex_to_bytes(text : String) -> Bytes? {
  let n = text.length()
  if n % 2 != 0 {
    return None
  }
  let out = FixedArray::make(n / 2, b'\x00')
  let mut i = 0
  while i < n / 2 {
    let hi = hex_value(text[i * 2].to_int())
    let lo = hex_value(text[i * 2 + 1].to_int())
    if hi < 0 || lo < 0 {
      return None
    }
    out[i] = ((hi << 4) | lo).to_byte()
    i = i + 1
  }
  Some(Bytes::from_array(out[:]))
}

///|
/// The bytes of two buffers, one after the other.
pub fn bytes_concat(a : Bytes, b : Bytes) -> Bytes {
  let out = FixedArray::make(a.length() + b.length(), b'\x00')
  let mut i = 0
  while i < a.length() {
    out[i] = a.at(i)
    i = i + 1
  }
  let mut j = 0
  while j < b.length() {
    out[a.length() + j] = b.at(j)
    j = j + 1
  }
  Bytes::from_array(out[:])
}

///|
/// The bytes of `count` zeros.
pub fn zero_bytes(count : Int32) -> Bytes {
  let out = FixedArray::make(count, b'\x00')
  Bytes::from_array(out[:])
}
