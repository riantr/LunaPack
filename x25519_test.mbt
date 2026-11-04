///|
/// The X25519 vectors of RFC 7748 section 5.2.
test "x25519 matches the RFC 7748 vectors" {
  let alice_private = hex_bytes(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let alice_public = hex_bytes(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  let bob_private = hex_bytes(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let bob_public = hex_bytes(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  // The public key of each side.
  assert_true(
    @LunaPack.bytes_to_hex(@LunaPack.x25519_public_key(alice_private)) ==
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  assert_true(
    @LunaPack.bytes_to_hex(@LunaPack.x25519_public_key(bob_private)) ==
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  // And the shared secret, from both sides.
  assert_true(
    @LunaPack.bytes_to_hex(@LunaPack.x25519(alice_private, bob_public)) ==
    shared,
  )
  assert_true(
    @LunaPack.bytes_to_hex(@LunaPack.x25519(bob_private, alice_public)) ==
    shared,
  )
}

///|
/// The X25519 of the reference implementation.
///
/// The vectors are the ones of the OpenSSH port of the curve, which the
/// reference project this package follows carries. The point of every
/// vector has its most significant bit clear, because that reference
/// follows OpenSSH and does not mask it as RFC 7748 asks.
test "x25519 matches the reference implementation" {
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "6ba5bdff0a74c60325eac00ee552f17a3b92956c38a3fefcc5e7a05cd56c4e70",
        ),
        hex_bytes(
          "12a1fc06b3fcc3df637e06eb719edf143537afde470284be205528bc9fd37b64",
        ),
      ),
    ) ==
    "b7c31db4e06f07a86e3fa803a9f36dea4b9602a84b6324354ffa8642ff36374d",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "7254349571c22e3fc5308136d0679f789b68a1ef102c55009a09f9583dca949c",
        ),
        hex_bytes(
          "54054587021f8be5ee86f14a31e5cb8c5894d6220d9566b76386ebb264760403",
        ),
      ),
    ) ==
    "cdbc667eda0d0806c28214019eda619a5de9c20df5fe49da3781ae6bd9bd6f7b",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "a2a3a40a61643162ad83e74f6825f557b7e1d32fad7acd6322674f7e1efe034d",
        ),
        hex_bytes(
          "0e5e80a294c605b1580d5a084cbe86e71c1d547f5aee18aecb002473f47f956e",
        ),
      ),
    ) ==
    "cce62b9a2ccf5ff449fb52fc0c35ad376480b1086a6a20076bb6459277dfd034",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "16f79ebf7ebce0cbf111856a79021b671c355638d2dd1c7c01f788304e1162b2",
        ),
        hex_bytes(
          "ea418fec79846771322d24f6d97e84bb90cb524741478a5208c23f8bcc808711",
        ),
      ),
    ) ==
    "fdf4d5d5226774fc2d671eafa258950586ca72de6ee70088f64289398d12bb57",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "5912a36da302e80b2343f426d92e8ae4c16e3304e34963b7a6be6f8c3242976a",
        ),
        hex_bytes(
          "17e172208089beba314185896509c7afba8ab87c9d2039ec2532c5673a282504",
        ),
      ),
    ) ==
    "e49d8a06f216afbbaf88ff7182e635342f3e94cc56c046213a2fcba355030205",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "950da51ca1f44d62771cd8ba796bd3d4cfd442cd61efe62ca141ca138cbaf2df",
        ),
        hex_bytes(
          "330bcaed72de2e7a3c64006cc1f90c3087cb841181e453b93d378844aec4991f",
        ),
      ),
    ) ==
    "cebfac2f5b7225397e4cdcacde613857005aff818298a8b7e5703e8076d7636c",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "25dd79050b7cd45a9acab92be0574a8998b74487ae689c243d6111f8ab07e6b8",
        ),
        hex_bytes(
          "6334252d02c931f4676d8df5d56e513a471bd84c80625a2d1dfd35a6f81dd341",
        ),
      ),
    ) ==
    "2c1f07a337a2bf0e4b9329a02fd3915335278911ee680fb809cbac267b005408",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "d38ef756417eec0c11edabf70736118297532b417729bae24e420d91d605c928",
        ),
        hex_bytes(
          "a1acbba0b75e44f02ada923fa4b1fdd9cd1e66ccd5b76e8166495657a341e34b",
        ),
      ),
    ) ==
    "04cd89e8db33e6c347f3f1a7c4157faf453c37933d2dfff09b76bdd95938292a",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "eefc8ed3c764951d2f269d3a3038cec9a54823616855ee4b8eb98493e3f005fd",
        ),
        hex_bytes(
          "daf2519d9f942bca9272cdba5452ed8ae1a64ee3fea92789501c1e6804af5a3a",
        ),
      ),
    ) ==
    "012ed07f20b2c5489e11a86ede6d48c0272a613efae4a204556eca898c55d14c",
  )
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "2af8c3205018441066ed350d61af491ff01184411915e56fcf4f149a73ef9a51",
        ),
        hex_bytes(
          "50e864f164bb801b7151615be38fedd83550526f237a9c0338f59307707afd00",
        ),
      ),
    ) ==
    "9b85b08cb7f96db3c2d83649164eb8ba8de29959cf90919fca9321e69170c470",
  )
}

///|
/// The first single shot vector of RFC 7748 section 5.2.
test "x25519 matches the first RFC 7748 vector" {
  assert_true(
    @LunaPack.bytes_to_hex(
      @LunaPack.x25519(
        hex_bytes(
          "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        ),
        hex_bytes(
          "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        ),
      ),
    ) ==
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
  )
}

///|
/// The iterated test of RFC 7748 section 5.2.
///
/// The rule of the RFC is that every iteration sets k to the result of
/// the call and u to the old value of k.
test "x25519 matches the iterated test of RFC 7748" {
  let start = "0900000000000000000000000000000000000000000000000000000000000000"
  let mut k = hex_bytes(start)
  let mut u = hex_bytes(start)
  // After one iteration, which is the value the RFC gives.
  let mut i = 0
  while i < 10 {
    let next = @LunaPack.x25519(k, u)
    u = k
    k = next
    i = i + 1
    if i == 1 {
      assert_true(
        @LunaPack.bytes_to_hex(k) ==
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
      )
    }
  }
  // And after ten, which is the value the reference implementation gives.
  assert_true(
    @LunaPack.bytes_to_hex(k) ==
    "7b96f292a115e83e78560105869c00b0f4fb2cd10e385b8c64bf047b0c0e1113",
  )
}
