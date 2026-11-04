// The tests of the cryptographic primitives.
//
// Every primitive is checked against the vector that the standard it comes
// from publishes, because an implementation that is self-consistent but
// wrong is worse than no implementation at all.

///|
/// The bytes of a hex string.
fn hex_bytes(s : String) -> Bytes {
  @LunaPack.hex_to_bytes(s).unwrap()
}

///|
/// The SHA-512 of the empty input and of "abc".
test "sha512 matches the FIPS 180-4 vectors" {
  assert_true(
    @LunaPack.sha512_hex(hex_bytes("")) ==
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
  assert_true(
    @LunaPack.sha512_hex(hex_bytes("616263")) ==
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
}

///|
/// A message of 112 bytes, which is the length that makes the padding
/// reach into a second block.
test "sha512 of a message that spans two blocks" {
  let data = hex_bytes(
    "61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475",
  )
  assert_true(
    @LunaPack.sha512_hex(data) ==
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
  )
}

///|
/// A message of many blocks, which is the length that exercises the
/// length field of the padding.
test "sha512 of a long message" {
  let data = pseudo_random(200000, 7)
  assert_true(
    @LunaPack.sha512_hex(data) ==
    "50ab1d45d85885b33d2dbea2762af252afa6ce7f69b55a11036a02491a881028826e0fe558fc4f7dc1fa7d1db648c40b2f27656085e8044108091d0f666c9862",
  )
}

///|
/// The HMAC-SHA512 vectors of RFC 4231.
test "hmac-sha512 matches the RFC 4231 vectors" {
  // key 20 bytes, data 8 bytes
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hmac_sha512(
        hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        hex_bytes("4869205468657265"),
      ),
    ) ==
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
  )
  // key 4 bytes, data 28 bytes
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hmac_sha512(
        hex_bytes("4a656665"),
        hex_bytes("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),
      ),
    ) ==
    "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
  )
  // key 20 bytes, data 50 bytes
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hmac_sha512(
        hex_bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        hex_bytes(
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
      ),
    ) ==
    "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
  )
  // key 131 bytes, data 54 bytes
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hmac_sha512(
        hex_bytes(
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        hex_bytes(
          "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
        ),
      ),
    ) ==
    "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
  )
  // key 131 bytes, data 50 bytes
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hmac_sha512(
        hex_bytes(
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        hex_bytes(
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
      ),
    ) ==
    "0561688775ef4645d176e8334d4f568724dbf3a9409bb6495097bd61afa684f0b7c6471dabd5b68d3a0b080a465ed9fadb8b2541ba295b38100323b6c00bb85b",
  )
}

///|
/// The digest of data that is fed in pieces is the same as the digest of
/// the data as a whole.
test "sha512 of data that is fed in pieces" {
  let data = pseudo_random(1000, 11)
  let whole = @LunaPack.sha512_hex(data)
  // The pieces do not fall on the block boundary, so the pending bytes
  // have to be carried over.
  for piece in [1, 7, 63, 127, 128, 129, 200] {
    let digest = @LunaPack.Sha512::Sha512()
    let mut at = 0
    while at < data.length() {
      let end = if data.length() - at < piece {
        data.length()
      } else {
        at + piece
      }
      digest.update(slice_of(data, at, end))
      at = end
    }
    assert_true(@LunaPack.bytes_to_hex(digest.finish()) == whole)
  }
}

///|
/// Hex is what the fingerprints and the keys are written in.
test "hex survives the round trip" {
  let data = pseudo_random(300, 13)
  let text = @LunaPack.bytes_to_hex(data)
  assert_true(text.length() == 600)
  assert_true(@LunaPack.hex_to_bytes(text).unwrap() == data)
  assert_true(@LunaPack.hex_to_bytes("0g") is None)
  assert_true(@LunaPack.hex_to_bytes("abc") is None)
}

///|
/// The HKDF-SHA512 values that .NET produces for the same inputs.
///
/// The reference implementation this package follows derives its keys
/// with `HKDF.DeriveKey(HashAlgorithmName.SHA512, ...)`, so the values
/// below are the ones that implementation gives.
test "hkdf-sha512 matches the values of the reference implementation" {
  // case1
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hkdf_sha512(
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415"),
        hex_bytes("606162636465666768696a6b6c"),
        hex_bytes("b0b1b2b3b4b5b6b7b8b9"),
        42,
      ),
    ) ==
    "2d85baee53b50df40805b50189623f426d0f526b3853197964f538b8455d76cb2a07974435d687150dbb",
  )
  // case1-long
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hkdf_sha512(
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415"),
        hex_bytes("606162636465666768696a6b6c"),
        hex_bytes("b0b1b2b3b4b5b6b7b8b9"),
        100,
      ),
    ) ==
    "2d85baee53b50df40805b50189623f426d0f526b3853197964f538b8455d76cb2a07974435d687150dbb4f3382689b09686011a659b816af1773179f7b92830eedfb76d20991462bd889b8278004167aebbcf107234779679d69cfc961597c36b3de1130",
  )
  // case2-empty-salt
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hkdf_sha512(
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415"),
        hex_bytes(""),
        hex_bytes("b0b1b2b3b4b5b6b7b8b9"),
        42,
      ),
    ) ==
    "1f33777df977adb012d5493a494ba6e0657de7cc9a49f563971191abab52673a716155af44de9057094e",
  )
  // case3-empty-info
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hkdf_sha512(
        hex_bytes("000102030405060708090a0b0c0d0e0f101112131415"),
        hex_bytes("606162636465666768696a6b6c"),
        hex_bytes(""),
        42,
      ),
    ) ==
    "6d9abcea47167a7939eee6bf7b03d8f5cc12d2d569b3a6baf1886ae168700ee67a8420cb41435ce24589",
  )
  // case4-short
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.hkdf_sha512(
        hex_bytes("010203"),
        hex_bytes("040506"),
        hex_bytes("0708"),
        32,
      ),
    ) ==
    "9a286a13c009480c52be615ce0eec777693804b178a8dc002c3ba874fce51f0a",
  )
}

///|
/// The PBKDF2-HMAC-SHA512 values of RFC 6070, computed with the
/// reference implementation of the standard library.
test "pbkdf2-hmac-sha512 matches the reference values" {
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.pbkdf2_sha512(
        hex_bytes("70617373776f7264"),
        hex_bytes("73616c74"),
        1000,
        32,
      ),
    ) ==
    "afe6c5530785b6cc6b1c6453384731bd5ee432ee549fd42fb6695779ad8a1c5b",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.pbkdf2_sha512(
        hex_bytes("70617373776f7264"),
        hex_bytes("73616c74"),
        1000,
        64,
      ),
    ) ==
    "afe6c5530785b6cc6b1c6453384731bd5ee432ee549fd42fb6695779ad8a1c5bf59de69c48f774efc4007d5298f9033c0241d5ab69305e7b64eceeb8d834cfec",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.pbkdf2_sha512(
        hex_bytes("70617373776f726450415353574f524470617373776f7264"),
        hex_bytes(
          "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74",
        ),
        4096,
        40,
      ),
    ) ==
    "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd953",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.pbkdf2_sha512(
        hex_bytes("7061737300776f7264"),
        hex_bytes("7361006c74"),
        4096,
        16,
      ),
    ) ==
    "9d9e9c4cd21fe4be24d5b8244c759665",
  )
}

///|
/// The ChaCha20 vector of RFC 8439 section 2.4.2.
test "chacha20 matches the RFC 8439 vector" {
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.chacha20_xor(
        hex_bytes(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ),
        hex_bytes("000000000000004a00000000"),
        1U,
        hex_bytes(
          "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        ),
      ),
    ) ==
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
  )
}

///|
/// The Poly1305 vector of RFC 8439 section 2.5.2.
test "poly1305 matches the RFC 8439 vector" {
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.poly1305(
        hex_bytes(
          "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        ),
        hex_bytes(
          "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
        ),
      ),
    ) ==
    "a8061dc1305136c6c22b8baf0c0127a9",
  )
}

///|
/// The authenticated encryption vector of RFC 8439 section 2.8.2.
test "chacha20-poly1305 matches the RFC 8439 vector" {
  let sealed_data = @LunaPack.chacha20poly1305_seal(
    hex_bytes(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    ),
    hex_bytes("070000004041424344454647"),
    hex_bytes(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    ),
    hex_bytes("50515253c0c1c2c3c4c5c6c7"),
  )
  assert_true(
    @LunaPack.bytes_to_hex(sealed_data) ==
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
  )
}

///|
/// A sealed_data text is opened again, and a damaged one is refused.
test "chacha20-poly1305 opens what it sealed_data" {
  let key = hex_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let nonce = hex_bytes("070000004041424344454647")
  let text = pseudo_random(1000, 17)
  let aad = hex_bytes("50515253c0c1c2c3c4c5c6c7")
  let sealed_data = @LunaPack.chacha20poly1305_seal(key, nonce, text, aad)
  let back = @LunaPack.chacha20poly1305_open(key, nonce, sealed_data, aad)
  assert_true(back == Some(text))
  // A tag that does not match is refused.
  let broken = FixedArray::make(sealed_data.length(), b'\x00')
  let mut i = 0
  while i < sealed_data.length() {
    broken[i] = sealed_data.at(i)
    i = i + 1
  }
  broken[sealed_data.length() - 1] = (broken[sealed_data.length() - 1].to_int() ^
  0xff).to_byte()
  assert_true(
    @LunaPack.chacha20poly1305_open(
      key,
      nonce,
      Bytes::from_array(broken[:]),
      aad,
    )
    is None,
  )
  // So is a different key.
  assert_true(
    @LunaPack.chacha20poly1305_open(
      hex_bytes(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
      nonce,
      sealed_data,
      aad,
    )
    is None,
  )
}
