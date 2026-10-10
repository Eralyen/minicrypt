globals.isGH = true
import_code("./MiniTest/MiniTest.src")
import_code("../src/chacha20-poly1305.ms")
import_code("../src/encode.ms")

// https://www.rfc-editor.org/info/rfc8439/#section-2.1.1
test_rfc8439_quarter_round = function
    bitwiseHexToInt = function(h)
        h = h[2:] //removes the '0x'
        c = minicrypt.Encode.HEX2BYTE
        return c[h[6:8]] + c[h[4:6]] * 256 + c[h[2:4]] * 65536 + c[h[0:2]] * 16777216
    end function
    bitwiseIntToHex = function(i)
        c = minicrypt.Encode.BYTE2HEX
        b1 = i % 256
        i = (i - b1) / 256
        b2 = i % 256
        i = (i - b2) / 256
        b3 = i % 256
        i = (i - b3) / 256
        b4 = i % 256
        return c[b4] + c[b3] + c[b2] + c[b1]
    end function
    a = bitwiseHexToInt("0x11111111")
    b = bitwiseHexToInt("0x01020304")
    c = bitwiseHexToInt("0x9b8d6f43")
    d = bitwiseHexToInt("0x01234567")
    x = [a, b, c, d]
    
    minicrypt.ChaCha.QR(x, 0, 1, 2, 3)
    a2 = "0x" + bitwiseIntToHex(x[0])
    b2 = "0x" + bitwiseIntToHex(x[1])
    c2 = "0x" + bitwiseIntToHex(x[2])
    d2 = "0x" + bitwiseIntToHex(x[3])
    
    // Expected results from the test vector
    A = "0xea2a92f4"
    B = "0xcb1cf8ce"
    C = "0x4581472e"
    D = "0x5881c4bb"

    expectEqual(a2, A, "a")
    expectEqual(b2, B, "b")
    expectEqual(c2, C, "c")
    expectEqual(d2, D, "d")
end function
TEST "RFC 8439 - Quarter Round", @test_rfc8439_quarter_round

// https://www.rfc-editor.org/info/rfc8439/#section-2.2.1
test_rfc8439_state_quarter_round = function
    bitwiseHexToInt = function(h)
        c = minicrypt.Encode.HEX2BYTE
        return c[h[6:8]] + c[h[4:6]] * 256 + c[h[2:4]] * 65536 + c[h[0:2]] * 16777216
    end function
    sample_state = [
        "879531e0", "c5ecf37d", "516461b1", "c9a62f8a",
        "44c20ef3", "3390af7f", "d9fc690b", "2a5f714c",
        "53372767", "b00a5631", "974c541a", "359e9963",
        "5c971061", "3d631689", "2098d9d6", "91dbd320",
       ]
    expected_state = [
        "879531e0", "c5ecf37d", "bdb886dc", "c9a62f8a",
        "44c20ef3", "3390af7f", "d9fc690b", "cfacafd2",
        "e46bea80", "b00a5631", "974c541a", "359e9963",
        "5c971061", "ccc07c79", "2098d9d6", "91dbd320",
    ]
    sample_state_b32 = []
    for s in sample_state
        sample_state_b32.push(bitwiseHexToInt(s))
    end for
    minicrypt.ChaCha.QR(sample_state_b32, 2, 7, 8, 13)
    expectEqual(minicrypt.Encode.B32ToHex(sample_state_b32), expected_state)
end function
TEST "RFC 8439 - Quarter Round on the ChaCha State", @test_rfc8439_state_quarter_round

// https://www.rfc-editor.org/info/rfc8439/#section-2.3.2
test_rfc8439_chacha_block = function
    key = minicrypt.Encode.hexBytesToB32("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:09:00:00:00:4a:00:00:00:00")
    counter = 1
    output = [0] * 16
    minicrypt.ChaCha.ROUNDS = 20
    state = minicrypt.ChaCha.assembleState(key, nonce, counter)
    expected_state = [
        "61707865", "3320646e", "79622d32", "6b206574",
        "03020100", "07060504", "0b0a0908", "0f0e0d0c",
        "13121110", "17161514", "1b1a1918", "1f1e1d1c",
        "00000001", "09000000", "4a000000", "00000000",
        ]
    expectEqual(minicrypt.Encode.B32ToHex(state), expected_state, "State initialization")

    expected_final = [
        "e4e7f110", "15593bd1", "1fdd0f50", "c47120a3",
        "c7f4d1c7", "0368c033", "9aaa2204", "4e6cd4c3",
        "466482d2", "09aa9f07", "05d7c214", "a2028bd9",
        "d19c12b5", "b94e16de", "e883d0cb", "4e3c50a2",
        ]
    minicrypt.ChaCha.chachaBlock(output, state)
    expectEqual(minicrypt.Encode.B32ToHex(output), expected_final, "State after 20 ChaChaBlock rounds + addition")
end function
TEST "RFC 8439 - ChaCha20 Block Function", @test_rfc8439_chacha_block

// https://www.rfc-editor.org/info/rfc8439/#section-2.4.2
test_rfc8439_chacha_cipher = function
    minicrypt.ChaCha.ROUNDS = 20
    key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".replace(":", "")
    nonce = "00:00:00:00:00:00:00:4a:00:00:00:00".replace(":", "")
    counter = 1
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext, "8bit", "base64", nonce, counter)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext, "8bit")
    ciphertext_len = minicrypt.Encode.fromBase64(ciphertext)[1]
    expectEqual(ciphertext_len-20, plaintext.len, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext)
end function
TEST "RFC 8439 - ChaCha20 Cipher", @test_rfc8439_chacha_cipher

// https://www.rfc-editor.org/info/rfc8439/#section-2.5.2
test_rfc8439_poly1305 = function
    key = minicrypt.Encode.hexBytesToB32("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b")
    msg = minicrypt.Encode.encodeText8("Cryptographic Forum Research Group")[0]
    tag = minicrypt.Encode.hexBytesToB32("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")
    expectEqual(minicrypt.Poly1305.macRaw(key, msg, 34), tag)
end function
TEST "RFC 8439 - Poly1305", @test_rfc8439_poly1305

// https://www.rfc-editor.org/info/rfc8439/#section-2.6.2
test_rfc8439_poly1305_keygen = function
    key = minicrypt.Encode.hexBytesToB32("80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:01:02:03:04:05:06:07")
    expected = minicrypt.Encode.hexBytesToB32("8a:d5:a0:8b:90:5f:81:cc:81:50:40:27:4a:b2:94:71:a8:33:b6:37:e3:fd:0d:a5:08:db:b8:e2:fd:d1:a6:46")
    expectEqual(minicrypt.ChaCha20Poly1305.keygen(key, nonce), expected)
end function
TEST "RFC 8439 - Poly1305 Key Generation", @test_rfc8439_poly1305_keygen

// https://www.rfc-editor.org/info/rfc8439/#section-2.8.2
test_rfc8439_aead = function
    plaintext = minicrypt.Encode.encodeText8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")[0]
    plaintext_len = 114
    aad = minicrypt.Encode.hexBytesToB32("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7")
    aad_len = 12
    key = minicrypt.Encode.hexBytesToB32("80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f")
    IV = "40:41:42:43:44:45:46:47"
    constant = "07:00:00:00"
    nonce = minicrypt.Encode.hexBytesToB32(constant + ":" + IV)
    counter = 1
    res = minicrypt.ChaCha20Poly1305.encryptRaw(key, nonce, aad, aad_len, plaintext, plaintext_len)
    aead = res[0]
    mac = res[1]
    aead_expected = minicrypt.Encode.hexBytesToB32("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7:00:00:00:00:d3:1a:8d:34:64:8e:60:db:7b:86:af:bc:53:ef:7e:c2:a4:ad:ed:51:29:6e:08:fe:a9:e2:b5:a7:36:ee:62:d6:3d:be:a4:5e:8c:a9:67:12:82:fa:fb:69:da:92:72:8b:1a:71:de:0a:9e:06:0b:29:05:d6:a5:b6:7e:cd:3b:36:92:dd:bd:7f:2d:77:8b:8c:98:03:ae:e3:28:09:1b:58:fa:b3:24:e4:fa:d6:75:94:55:85:80:8b:48:31:d7:bc:3f:f4:de:f0:8e:4b:7a:9d:e5:76:d2:65:86:ce:c6:4b:61:16:00:00:00:00:00:00:00:00:00:00:00:00:00:00:0c:00:00:00:00:00:00:00:72:00:00:00:00:00:00:00")
    
    expectEqual(aead, aead_expected, "AEAD")
end function
TEST "RFC 8439 - AEAD_CHACHA20_POLY1305", @test_rfc8439_aead

// ADDITIONAL TEST VECTORS
// https://www.rfc-editor.org/info/rfc8439/#appendix-A

// https://www.rfc-editor.org/info/rfc8439/#appendix-A.1
test_rfc8439_chacha_block_vectors = function

    // TEST VECTOR #1

    key = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00")
    counter = 0
    expected_state = [
        "ade0b876", "903df1a0", "e56a5d40", "28bd8653",
        "b819d2bd", "1aed8da0", "ccef36a8", "c70d778b",
        "7c5941da", "8d485751", "3fe02477", "374ad8b8",
        "f4b8436a", "1ca11815", "69b687c3", "8665eeb2",
    ]
    state = minicrypt.ChaCha.assembleState(key, nonce, counter)
    final_state = [0] * 16
    minicrypt.ChaCha.chachaBlock(final_state, state)

    expectEqual(minicrypt.Encode.B32ToHex(final_state), expected_state, "Test Vector #1")
    // The keystream is just a different way to write the ChaCha state.
    // If the test above this comment passes, then the keystream is also correct

    // TEST VECTOR #2

    key = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00")
    counter = 1
    expected_state = [
        "bee7079f", "7a385155", "7c97ba98", "0d082d73",
        "a0290fcb", "6965e348", "3e53c612", "ed7aee32",
        "7621b729", "434ee69c", "b03371d5", "d539d874",
        "281fed31", "45fb0a51", "1f0ae1ac", "6f4d794b",
    ]
    state = minicrypt.ChaCha.assembleState(key, nonce, counter)
    final_state = [0] * 16
    minicrypt.ChaCha.chachaBlock(final_state, state)

    expectEqual(minicrypt.Encode.B32ToHex(final_state), expected_state, "Test Vector #2")
    // The keystream is just a different way to write the ChaCha state.
    // If the test above this comment passes, then the keystream is also correct
    
    // TEST VECTOR #3

    key = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00")
    counter = 1
    expected_state = [
        "2452eb3a", "9249f8ec", "8d829d9b", "ddd4ceb1",
        "e8252083", "60818b01", "f38422b8", "5aaa49c9",
        "bb00ca8e", "da3ba7b4", "c4b592d1", "fdf2732f",
        "4436274e", "2561b3c8", "ebdd4aa6", "a0136c00",
        ]
    state = minicrypt.ChaCha.assembleState(key, nonce, counter)
    final_state = [0] * 16
    minicrypt.ChaCha.chachaBlock(final_state, state)

    expectEqual(minicrypt.Encode.B32ToHex(final_state), expected_state, "Test Vector #3")
    // The keystream is just a different way to write the ChaCha state.
    // If the test above this comment passes, then the keystream is also correct

    // TEST VECTOR #4

    key = minicrypt.Encode.hexBytesToB32("00:ff:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00")
    counter = 2
    expected_state = [
        "fb4dd572", "4bc42ef1", "df922636", "327f1394",
        "a78dea8f", "5e269039", "a1bebbc1", "caf09aae",
        "a25ab213", "48a6b46c", "1b9d9bcb", "092c5be6",
        "546ca624", "1bec45d5", "87f47473", "96f0992e",
    ]
    state = minicrypt.ChaCha.assembleState(key, nonce, counter)
    final_state = [0] * 16
    minicrypt.ChaCha.chachaBlock(final_state, state)

    expectEqual(minicrypt.Encode.B32ToHex(final_state), expected_state, "Test Vector #4")
    // The keystream is just a different way to write the ChaCha state.
    // If the test above this comment passes, then the keystream is also correct

    // TEST VECTOR #5

    key = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:02")
    counter = 0
    expected_state = [
        "374dc6c2", "3736d58c", "b904e24a", "cd3f93ef",
        "88228b1a", "96a4dfb3", "5b76ab72", "c727ee54",
        "0e0e978a", "f3145c95", "1b748ea8", "f786c297",
        "99c28f5f", "628314e8", "398a19fa", "6ded1b53",
        ]
    state = minicrypt.ChaCha.assembleState(key, nonce, counter)
    final_state = [0] * 16
    minicrypt.ChaCha.chachaBlock(final_state, state)

    expectEqual(minicrypt.Encode.B32ToHex(final_state), expected_state, "Test Vector #5")
    // The keystream is just a different way to write the ChaCha state.
    // If the test above this comment passes, then the keystream is also correct
end function
TEST "RFC 8439 - Additional Vectors: The ChaCha20 Block Functions", @test_rfc8439_chacha_block_vectors

test_rfc8439_chacha_encryption_vectors = function

    // TEST VECTOR #1

    key = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00")
    counter = 0
    plaintext = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
    plaintext_len = 64
    ciphertext_expected = minicrypt.Encode.hexBytesToB32("76:b8:e0:ad:a0:f1:3d:90:40:5d:6a:e5:53:86:bd:28:bd:d2:19:b8:a0:8d:ed:1a:a8:36:ef:cc:8b:77:0d:c7:da:41:59:7c:51:57:48:8d:77:24:e0:3f:b8:d8:4a:37:6a:43:b8:f4:15:18:a1:1c:c3:87:b6:69:b2:ee:65:86")
    ciphertext = minicrypt.ChaCha.chacha(key, nonce, plaintext, plaintext_len, counter)
    expectEqual(ciphertext, ciphertext_expected, "Test Vector #1")

    // TEST VECTOR #2

    key = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01".replace(":", "")
    nonce = "00:00:00:00:00:00:00:00:00:00:00:02".replace(":", "")
    counter = 1
    plaintext = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an " + char(34) + "IETF Contribution" + char(34) + ". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to"
    ciphertext_expected = [
        "a3:fb:f0:7d:f3:fa:2f:de:4f:37:6c:a2:3e:82:73:70",
        "41:60:5d:9f:4f:4f:57:bd:8c:ff:2c:1d:4b:79:55:ec",
        "2a:97:94:8b:d3:72:29:15:c8:f3:d3:37:f7:d3:70:05",
        "0e:9e:96:d6:47:b7:c3:9f:56:e0:31:ca:5e:b6:25:0d",
        "40:42:e0:27:85:ec:ec:fa:4b:4b:b5:e8:ea:d0:44:0e",
        "20:b6:e8:db:09:d8:81:a7:c6:13:2f:42:0e:52:79:50",
        "42:bd:fa:77:73:d8:a9:05:14:47:b3:29:1c:e1:41:1c",
        "68:04:65:55:2a:a6:c4:05:b7:76:4d:5e:87:be:a8:5a",
        "d0:0f:84:49:ed:8f:72:d0:d6:62:ab:05:26:91:ca:66",
        "42:4b:c8:6d:2d:f8:0e:a4:1f:43:ab:f9:37:d3:25:9d",
        "c4:b2:d0:df:b4:8a:6c:91:39:dd:d7:f7:69:66:e9:28",
        "e6:35:55:3b:a7:6c:5c:87:9d:7b:35:d4:9e:b2:e6:2b",
        "08:71:cd:ac:63:89:39:e2:5e:8a:1e:0e:f9:d5:28:0f",
        "a8:ca:32:8b:35:1c:3c:76:59:89:cb:cf:3d:aa:8b:6c",
        "cc:3a:af:9f:39:79:c9:2b:37:20:fc:88:dc:95:ed:84",
        "a1:be:05:9c:64:99:b9:fd:a2:36:e7:e8:18:b0:4b:0b",
        "c3:9c:1e:87:6b:19:3b:fe:55:69:75:3f:88:12:8c:c0",
        "8a:aa:9b:63:d1:a1:6f:80:ef:25:54:d7:18:9c:41:1f",
        "58:69:ca:52:c5:b8:3f:a3:6f:f2:16:b9:c1:d3:00:62",
        "be:bc:fd:2d:c5:bc:e0:91:19:34:fd:a7:9a:86:f6:e6",
        "98:ce:d7:59:c3:ff:9b:64:77:33:8f:3d:a4:f9:cd:85",
        "14:ea:99:82:cc:af:b3:41:b2:38:4d:d9:02:f3:d1:ab",
        "7a:c6:1d:d2:9c:6f:21:ba:5b:86:2f:37:30:e3:7c:fd",
        "c4:fd:80:6c:22:f2:21",
    ]
    ciphertext_expected_b32 = []
    for c in ciphertext_expected
        ciphertext_expected_b32 = ciphertext_expected_b32 + minicrypt.Encode.hexBytesToB32(c)
    end for
    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext, "8bit", "base64", nonce, counter)
    expectEqual(minicrypt.Encode.fromBase64(ciphertext)[0][5:], ciphertext_expected_b32, "Test Vector #2")

    // TEST VECTOR #3

    key = "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 " +
            "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
        key = key.replace(" ", "")
    nonce = "00 00 00 00 00 00 00 00 00 00 00 02".replace(" ", "")
    counter = 42
    plaintext = "'Twas brillig, and the slithy toves" + char(10) +
                "Did gyre and gimble in the wabe:"    + char(10) +
                "All mimsy were the borogoves,"       + char(10) +
                "And the mome raths outgrabe."
    ciphertext_expected = [
        "62:e6:34:7f:95:ed:87:a4:5f:fa:e7:42:6f:27:a1:df",
        "5f:b6:91:10:04:4c:0d:73:11:8e:ff:a9:5b:01:e5:cf",
        "16:6d:3d:f2:d7:21:ca:f9:b2:1e:5f:b1:4c:61:68:71",
        "fd:84:c5:4f:9d:65:b2:83:19:6c:7f:e4:f6:05:53:eb",
        "f3:9c:64:02:c4:22:34:e3:2a:35:6b:3e:76:43:12:a6",
        "1a:55:32:05:57:16:ea:d6:96:25:68:f8:7d:3f:3f:77",
        "04:c6:a8:d1:bc:d1:bf:4d:50:d6:15:4b:6d:a7:31:b1",
        "87:b5:8d:fd:72:8a:fa:36:75:7a:79:7a:c1:88:d1",
    ]
    ciphertext_expected_b32 = []
    for c in ciphertext_expected
        ciphertext_expected_b32 = ciphertext_expected_b32 + minicrypt.Encode.hexBytesToB32(c)
    end for
    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext, "8bit", "base64", nonce, counter)
    expectEqual(minicrypt.Encode.fromBase64(ciphertext)[0][5:], ciphertext_expected_b32, "Test Vector #3")
end function
TEST "RFC 8439 - Additional Vectors: ChaCha20 Encryption", @test_rfc8439_chacha_encryption_vectors


// https://www.rfc-editor.org/info/rfc8439/#appendix-A.3
test_rfc8439_poly1305_mac_vectors = function
    check = function(key, msg, byte_count, tag, note)
        expected = minicrypt.Encode.hexBytesToB32(tag)
        actual = minicrypt.Poly1305.macRaw(key, msg, byte_count)
        expectEqual(actual, expected, note)
    end function

    // Test Vector #1
    key = [0] * 8
    data = [0] * 16
    data_byte_count = 64
    zero_tag = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    expected_tag = zero_tag
    check(key, data, data_byte_count, expected_tag, "Test Vector #1")

    // Test Vectors #2 and #3 use the same 375-byte message.
    long_text = "Any submission to the IETF intended by the Contributor for publication " +
                "as all or part of an IETF Internet-Draft or RFC and any statement " +
                "made within the context of an IETF activity is considered an " +
                char(34) + "IETF Contribution" + char(34) +
                ". Such statements include oral statements in IETF sessions, as well " +
                "as written and electronic communications made at any time or place, " +
                "which are addressed to"
    long_msg = minicrypt.Encode.encodeText8(long_text)

    // Test Vector #2
    r = [0] * 4
    s_hex = "36:e5:f6:b5:c5:e0:60:70:f0:ef:ca:96:22:7a:86:3e"
    s = minicrypt.Encode.hexBytesToB32(s_hex)
    key = r + s
    data = long_msg[0]
    data_byte_count = long_msg[1]
    expected_tag = s_hex
    check(key, data, data_byte_count, expected_tag, "Test Vector #2")

    // Test Vector #3
    r = minicrypt.Encode.hexBytesToB32(s_hex)
    s = [0] * 4
    key = r + s
    data = long_msg[0]
    data_byte_count = long_msg[1]
    expected_tag = "f3:47:7e:7c:d9:54:17:af:89:a6:b8:79:4c:31:0c:f0"
    check(key, data, data_byte_count, expected_tag, "Test Vector #3")

    // Test Vector #4
    poem = "'Twas brillig, and the slithy toves" + char(10) +
           "Did gyre and gimble in the wabe:" + char(10) +
           "All mimsy were the borogoves," + char(10) +
           "And the mome raths outgrabe."
    poem_msg = minicrypt.Encode.encodeText8(poem)
    key = minicrypt.Encode.hexBytesToB32("1c:92:40:a5:eb:55:d3:8a:f3:33:88:86:04:f6:b5:f0:47:39:17:c1:40:2b:80:09:9d:ca:5c:bc:20:70:75:c0")
    data = poem_msg[0]
    data_byte_count = poem_msg[1]
    expected_tag = "45:41:66:9a:7e:aa:ee:61:e7:08:dc:7c:bc:c5:eb:62"
    check(key, data, data_byte_count, expected_tag, "Test Vector #4")

    zero_s = [0] * 4
    r1 = [1, 0, 0, 0]
    r2 = [2, 0, 0, 0]
    ff16 = "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff"

    // Test Vector #5: 130-bit partial reduction.
    key = r2 + zero_s
    data = minicrypt.Encode.hexBytesToB32(ff16)
    data_byte_count = 16
    expected_tag = "03:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    check(key, data, data_byte_count, expected_tag, "Test Vector #5")

    // Test Vector #6: addition of S overflows 128 bits.
    key = r2 + [4294967295] * 4
    data = [2, 0, 0, 0]
    data_byte_count = 16
    expected_tag = "03:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    check(key, data, data_byte_count, expected_tag, "Test Vector #6")

    // Test Vector #7: carry from a lower data limb.
    key = r1 + zero_s
    data7_block1 = ff16
    data7_block2 = "f0:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff"
    data7_block3 = "11:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    data = minicrypt.Encode.hexBytesToB32(data7_block1 + ":" + data7_block2 + ":" + data7_block3)
    data_byte_count = 48
    expected_tag = "05:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    check(key, data, data_byte_count, expected_tag, "Test Vector #7")

    // Test Vector #8: final polynomial result is 2^130 - 5.
    data8_block2 = "fb:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe"
    data8_block3 = "01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01"
    data = minicrypt.Encode.hexBytesToB32(data7_block1 + ":" + data8_block2 + ":" + data8_block3)
    data_byte_count = 48
    expected_tag = zero_tag
    check(key, data, data_byte_count, expected_tag, "Test Vector #8")

    // Test Vector #9: final polynomial result is 2^130 - 6.
    key = r2 + zero_s
    data = minicrypt.Encode.hexBytesToB32("fd:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff")
    data_byte_count = 16
    expected_tag = "fa:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff"
    check(key, data, data_byte_count, expected_tag, "Test Vector #9")

    // Test Vectors #10 and #11: 131-bit intermediate and final reductions.
    r = minicrypt.Encode.hexBytesToB32("01:00:00:00:00:00:00:00:04:00:00:00:00:00:00:00")
    key = r + zero_s
    data_block1 = "e3:35:94:d7:50:5e:43:b9:00:00:00:00:00:00:00:00"
    data_block2 = "33:94:d7:50:5e:43:79:cd:01:00:00:00:00:00:00:00"
    data_block3 = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    data_prefix = data_block1 + ":" + data_block2 + ":" + data_block3

    // Test Vector #10 includes a final block containing 01.
    data_block4 = "01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    data = minicrypt.Encode.hexBytesToB32(data_prefix + ":" + data_block4)
    data_byte_count = 64
    expected_tag = "14:00:00:00:00:00:00:00:55:00:00:00:00:00:00:00"
    check(key, data, data_byte_count, expected_tag, "Test Vector #10")

    // Test Vector #11 ends after the first three blocks.
    data = minicrypt.Encode.hexBytesToB32(data_prefix)
    data_byte_count = 48
    expected_tag = "13:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    check(key, data, data_byte_count, expected_tag, "Test Vector #11")
end function
TEST "RFC 8439 - Additional Vectors: Poly1305 Message Authentication Code", @test_rfc8439_poly1305_mac_vectors

// https://www.rfc-editor.org/info/rfc8439/#appendix-A.4
test_rfc8439_poly1305_keygen_vectors = function
    minicrypt.ChaCha.ROUNDS = 20

    // Test Vector #1
    chacha_key = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00")
    expected_poly1305_key = minicrypt.Encode.hexBytesToB32("76:b8:e0:ad:a0:f1:3d:90:40:5d:6a:e5:53:86:bd:28:bd:d2:19:b8:a0:8d:ed:1a:a8:36:ef:cc:8b:77:0d:c7")
    actual_poly1305_key = minicrypt.ChaCha20Poly1305.keygen(chacha_key, nonce)
    expectEqual(actual_poly1305_key, expected_poly1305_key, "Test Vector #1")

    // Test Vector #2
    chacha_key = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:02")
    expected_poly1305_key = minicrypt.Encode.hexBytesToB32("ec:fa:25:4f:84:5f:64:74:73:d3:cb:14:0d:a9:e8:76:06:cb:33:06:6c:44:7b:87:bc:26:66:dd:e3:fb:b7:39")
    actual_poly1305_key = minicrypt.ChaCha20Poly1305.keygen(chacha_key, nonce)
    expectEqual(actual_poly1305_key, expected_poly1305_key, "Test Vector #2")

    // Test Vector #3
    chacha_key = minicrypt.Encode.hexBytesToB32("1c:92:40:a5:eb:55:d3:8a:f3:33:88:86:04:f6:b5:f0:47:39:17:c1:40:2b:80:09:9d:ca:5c:bc:20:70:75:c0")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:00:00:00:00:02")
    expected_poly1305_key = minicrypt.Encode.hexBytesToB32("96:5e:3b:c6:f9:ec:7e:d9:56:08:08:f4:d2:29:f9:4b:13:7f:f2:75:ca:9b:3f:cb:dd:59:de:aa:d2:33:10:ae")
    actual_poly1305_key = minicrypt.ChaCha20Poly1305.keygen(chacha_key, nonce)
    expectEqual(actual_poly1305_key, expected_poly1305_key, "Test Vector #3")
end function
TEST "RFC 8439 - Additional Vectors: Poly1305 Key Generation", @test_rfc8439_poly1305_keygen_vectors

// https://www.rfc-editor.org/info/rfc8439/#appendix-A.5
test_rfc8439_aead_decryption_vectors = function
    minicrypt.ChaCha.ROUNDS = 20

    // Key
    key = minicrypt.Encode.hexBytesToB32("1c:92:40:a5:eb:55:d3:8a:f3:33:88:86:04:f6:b5:f0:47:39:17:c1:40:2b:80:09:9d:ca:5c:bc:20:70:75:c0")

    // Nonce
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:01:02:03:04:05:06:07:08")

    // AAD
    aad = minicrypt.Encode.hexBytesToB32("f3:33:88:86:00:00:00:00:00:00:4e:91")
    aad_byte_count = 12

    // Ciphertext, grouped by RFC byte offsets
    ciphertext_hex = "64:a0:86:15:75:86:1a:f4:60:f0:62:c7:9b:e6:43:bd" +
                     ":5e:80:5c:fd:34:5c:f3:89:f1:08:67:0a:c7:6c:8c:b2" +
                     ":4c:6c:fc:18:75:5d:43:ee:a0:9e:e9:4e:38:2d:26:b0" +
                     ":bd:b7:b7:3c:32:1b:01:00:d4:f0:3b:7f:35:58:94:cf" +
                     ":33:2f:83:0e:71:0b:97:ce:98:c8:a8:4a:bd:0b:94:81" +
                     ":14:ad:17:6e:00:8d:33:bd:60:f9:82:b1:ff:37:c8:55" +
                     ":97:97:a0:6e:f4:f0:ef:61:c1:86:32:4e:2b:35:06:38" +
                     ":36:06:90:7b:6a:7c:02:b0:f9:f6:15:7b:53:c8:67:e4" +
                     ":b9:16:6c:76:7b:80:4d:46:a5:9b:52:16:cd:e7:a4:e9" +
                     ":90:40:c5:a4:04:33:22:5e:e2:82:a1:b0:a0:6c:52:3e" +
                     ":af:45:34:d7:f8:3f:a1:15:5b:00:47:71:8c:bc:54:6a" +
                     ":0d:07:2b:04:b3:56:4e:ea:1b:42:22:73:f5:48:27:1a" +
                     ":0b:b2:31:60:53:fa:76:99:19:55:eb:d6:31:59:43:4e" +
                     ":ce:bb:4e:46:6d:ae:5a:10:73:a6:72:76:27:09:7a:10" +
                     ":49:e6:17:d9:1d:36:10:94:fa:68:f0:ff:77:98:71:30" +
                     ":30:5b:ea:ba:2e:da:04:df:99:7b:71:4d:6c:6f:2c:29" +
                     ":a6:ad:5c:b4:02:2b:02:70:9b"
    ciphertext = minicrypt.Encode.hexBytesToB32(ciphertext_hex)
    ciphertext_byte_count = 265

    // Received authentication tag
    tag = minicrypt.Encode.hexBytesToB32("ee:ad:9d:67:89:0c:bb:22:39:23:36:fe:a1:85:1f:38")

    // Verify before decrypting, then check the recovered AAD and plaintext.
    aead = minicrypt.ChaCha20Poly1305.AEAD(aad, aad_byte_count, ciphertext, ciphertext_byte_count)
    expectEqual(minicrypt.ChaCha20Poly1305.verifyRaw(key, tag, nonce, aead), true, "Tag verification")

    result = minicrypt.ChaCha20Poly1305.decryptRaw(key, nonce, aead)
    expectEqual(result[0], aad, "AAD")
    expectEqual(result[1], aad_byte_count, "AAD length")
    expectEqual(result[2], minicrypt.Encode.hexBytesToB32(
        "49:6e:74:65:72:6e:65:74:2d:44:72:61:66:74:73:20" +
        ":61:72:65:20:64:72:61:66:74:20:64:6f:63:75:6d:65" +
        ":6e:74:73:20:76:61:6c:69:64:20:66:6f:72:20:61:20" +
        ":6d:61:78:69:6d:75:6d:20:6f:66:20:73:69:78:20:6d" +
        ":6f:6e:74:68:73:20:61:6e:64:20:6d:61:79:20:62:65" +
        ":20:75:70:64:61:74:65:64:2c:20:72:65:70:6c:61:63" +
        ":65:64:2c:20:6f:72:20:6f:62:73:6f:6c:65:74:65:64" +
        ":20:62:79:20:6f:74:68:65:72:20:64:6f:63:75:6d:65" +
        ":6e:74:73:20:61:74:20:61:6e:79:20:74:69:6d:65:2e" +
        ":20:49:74:20:69:73:20:69:6e:61:70:70:72:6f:70:72" +
        ":69:61:74:65:20:74:6f:20:75:73:65:20:49:6e:74:65" +
        ":72:6e:65:74:2d:44:72:61:66:74:73:20:61:73:20:72" +
        ":65:66:65:72:65:6e:63:65:20:6d:61:74:65:72:69:61" +
        ":6c:20:6f:72:20:74:6f:20:63:69:74:65:20:74:68:65" +
        ":6d:20:6f:74:68:65:72:20:74:68:61:6e:20:61:73:20" +
        ":2f:e2:80:9c:77:6f:72:6b:20:69:6e:20:70:72:6f:67" +
        ":72:65:73:73:2e:2f:e2:80:9d"), "Plaintext")
    expectEqual(result[3], ciphertext_byte_count, "Plaintext length")
end function
TEST "RFC 8439 - Additional Vectors: ChaCha20-Poly1305 AEAD Decryption", @test_rfc8439_aead_decryption_vectors

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if