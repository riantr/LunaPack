// Whitebox tests: they run inside the package scope and may use internal
// helpers that are not part of the public API.

///|
test "little-endian int64 encoding round-trips" {
  assert_true(le8_to_i64(i64_to_le8(0L), 0) == 0L)
  assert_true(le8_to_i64(i64_to_le8(1L), 0) == 1L)
  assert_true(le8_to_i64(i64_to_le8(255L), 0) == 255L)
  assert_true(le8_to_i64(i64_to_le8(256L), 0) == 256L)
  assert_true(le8_to_i64(i64_to_le8(-1L), 0) == -1L)
  assert_true(le8_to_i64(i64_to_le8(1793664000000L), 0) == 1793664000000L)
}

///|
test "the manifest footer encodes the offset and length" {
  let footer = i64_to_le8(49L) + i64_to_le8(359L)
  assert_true(footer.length() == 16)
  assert_true(le8_to_i64(footer, 0) == 49L)
  assert_true(le8_to_i64(footer, 8) == 359L)
}

///|
test "json escaping" {
  assert_true(json_escape("plain") == "plain")
  assert_true(json_escape("say \"hi\"") == "say \\\"hi\\\"")
  assert_true(json_escape("a\\b") == "a\\\\b")
  assert_true(json_escape("line\nbreak") == "line\\nbreak")
}

///|
test "the magic marker is exactly eight bytes" {
  assert_true(MAGIC.length() == 8)
  assert_true(magic_bytes().length() == 8)
  assert_true(utf8_bytes_to_string(magic_bytes()) == MAGIC)
}
