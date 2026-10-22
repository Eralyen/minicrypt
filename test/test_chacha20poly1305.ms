globals.isGH = true
import_code("./MiniTest/MiniTest.src")
import_code("../src/chacha20-poly1305.ms")
import_code("../src/encode.ms")

test_chacha20poly1305_encrypt_decrypt = function
    minicrypt.ChaCha.ROUNDS = 20
    key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".replace(":", "")
    nonce = "00:00:00:00:00:00:00:4a:00:00:00:00".replace(":", "")
    counter = 1
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext, "8bit", "base64", nonce, counter)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext, "8bit")
    ciphertext_len = minicrypt.Encode.fromBase64(ciphertext)[1]
    expectEqual(ciphertext_len-20, plaintext.len, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext, "Successive encryption and decryption 1")

    plaintext = plaintext[:-1]
    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext)
    expectEqual(minicrypt.Encode.fromBase64(ciphertext)[1]-20, plaintext.len*2, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext, "Successive encryption and decryption 2")
    
    plaintext = plaintext[:-1]    
    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext)
    expectEqual(minicrypt.Encode.fromBase64(ciphertext)[1]-20, plaintext.len*2, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext, "Successive encryption and decryption 3")
    
    plaintext = plaintext[:-1]    
    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext)
    expectEqual(minicrypt.Encode.fromBase64(ciphertext)[1]-20, plaintext.len*2, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext, "Successive encryption and decryption 4")
end function
TEST "CHACHA20-POLY1305 - ChaCha.encrypt - ChaCha.decrypt", @test_chacha20poly1305_encrypt_decrypt

test_chacha20poly1305_raw_aead = function
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
    expectTrue(minicrypt.ChaCha20Poly1305.verifyRaw(key, mac, nonce, aead), "Verification of authentic AEAD")

    aead_tampered = aead[:]
    aead_tampered[0] = aead_tampered[0] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verifyRaw(key, mac, nonce, aead_tampered), "Rejection of tampered AAD")

    aead_tampered = aead[:]
    aead_tampered[2] = aead_tampered[2] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verifyRaw(key, mac, nonce, aead_tampered), "Rejection of tampered AEAD")

    res = minicrypt.ChaCha20Poly1305.decryptRaw(key, nonce, aead)
    deciphered = res[2]
    expectEqual(deciphered, plaintext, "Deciphered text matches")
end function
TEST "CHACHA20-POLY1305 - ChaCha20Poly1305.*Raw", @test_chacha20poly1305_raw_aead

test_chacha20poly1305_aead_boundaries = function
    lengths = [0, 1, 3, 4, 15, 16, 17]
    for aad_len in lengths
        for ciphertext_len in lengths
            aad = minicrypt.Encode.encodeText8("a" * aad_len)[0]
            ciphertext = minicrypt.Encode.encodeText8("c" * ciphertext_len)[0]
            aead = minicrypt.ChaCha20Poly1305.AEAD(aad, aad_len, ciphertext, ciphertext_len)
            expected_aead_len = ceil(aad_len / 16) * 4 + ceil(ciphertext_len / 16) * 4 + 4
            expectEqual(aead.len, expected_aead_len, "Padded AEAD length")

            res = minicrypt.ChaCha20Poly1305.splitAEAD(aead)
            expectEqual(res[0], aad, "AAD length " + str(aad_len))
            expectEqual(res[1], aad_len, "AAD byte count " + str(aad_len))
            expectEqual(res[2], ciphertext, "Ciphertext length " + str(ciphertext_len))
            expectEqual(res[3], ciphertext_len, "Ciphertext byte count " + str(ciphertext_len))
        end for
    end for

    expectEqual(minicrypt.ChaCha20Poly1305.splitAEAD([0, 0, 0, 0]), [[], 0, [], 0], "Zero length AEAD")
    
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitAEAD([])), "error", "Reject short AEAD")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitAEAD([0, 0, 0])), "error", "Reject unpadded AEAD")
end function
TEST "CHACHA20-POLY1305 - AEAD split boundaries", @test_chacha20poly1305_aead_boundaries

test_chacha20poly1305_high_level_auth = function
    key = "171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c"
    nonce = [1, 2, 3]
    aad = "A" + char(0) + char(233)
    plaintext = "B" + char(0) + char(233) + char(65535)

    ciphertext = minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, aad, "16bit", "base64", nonce)
    expectEqual(minicrypt.ChaCha20Poly1305.decrypt(key, ciphertext), [plaintext, aad], "Default encoding round trip")
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, ciphertext), "Default encoding authenticates")
    expectEqual(minicrypt.ChaCha20Poly1305.getAAD(ciphertext), aad, "Default encoding retrieves AAD")

    encoded = minicrypt.Encode.fromBase64(ciphertext)
    tampered_aad = encoded[0][:]
    tampered_aad[7] = tampered_aad[7] + 1
    tampered_aad_ciphertext = minicrypt.Encode.toBase64(tampered_aad, encoded[1])
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, tampered_aad_ciphertext), "Reject changed AAD")

    tampered = encoded[0][:]
    tampered[0] = (tampered[0] + 1) % 4294967296
    tampered_ciphertext = minicrypt.Encode.toBase64(tampered, encoded[1])
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, tampered_ciphertext), "Reject changed authentication tag")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, tampered_ciphertext)), "error", "Do not decrypt an unauthenticated message")
    expectEqual(minicrypt.ChaCha20Poly1305.decrypt(key, tampered_ciphertext, false), [plaintext, aad], "Explicit verification bypass")
    expectFalse(minicrypt.ChaCha20Poly1305.verify("0000000000000000000000000000000000000000000000000000000000000000", ciphertext), "Reject wrong key")

    plaintext = "8-bit plaintext"
    ciphertext = minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, "", "8bit", "8bit", [4, 5, 6])
    expectEqual(minicrypt.ChaCha20Poly1305.decrypt(key, ciphertext, true, "8bit", "8bit"), [plaintext, ""], "8-bit transport round trip")
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, ciphertext, "8bit"), "8-bit transport authenticates")
    expectEqual(minicrypt.ChaCha20Poly1305.getAAD(ciphertext, "8bit", "8bit"), "", "8-bit transport retrieves empty AAD")

    for plaintext_len in [1, 15, 16, 17, 63, 64, 65]
        plaintext = "x" * plaintext_len
        ciphertext = minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, "boundary", "8bit", "base64", [plaintext_len, 10, 11])
        expectEqual(minicrypt.ChaCha20Poly1305.decrypt(key, ciphertext, true, "8bit"), [plaintext, "boundary"], "Plaintext byte length " + str(plaintext_len))
        expectTrue(minicrypt.ChaCha20Poly1305.verify(key, ciphertext), "Authenticates plaintext byte length " + str(plaintext_len))
    end for

    ciphertext = minicrypt.ChaCha20Poly1305.encrypt(key, "", "", "8bit", "base64", [7, 8, 9])
    expectEqual(minicrypt.ChaCha20Poly1305.decrypt(key, ciphertext, true, "8bit"), ["", ""], "Empty AAD and plaintext round trip")
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, ciphertext), "Empty message authenticates")
end function
TEST "CHACHA20-POLY1305 - High-level encodings and authentication", @test_chacha20poly1305_high_level_auth

test_chacha20poly1305_poly1305_encodings = function
    key = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    message = "MAC wrapper input"
    raw_key = minicrypt.Encode.encodeHex(key)[0]
    raw_message = minicrypt.Encode.encodeText8(message)
    expected = minicrypt.Poly1305.macRaw(raw_key, raw_message[0], raw_message[1])

    mac_b64 = minicrypt.Poly1305.mac(key, message, "8bit", "base64")
    expectEqual(minicrypt.Encode.fromBase64(mac_b64)[0], expected, "Base64 MAC output")

    mac_8bit = minicrypt.Poly1305.mac(key, message, "8bit", "8bit")
    expectEqual(minicrypt.Encode.encodeText8(mac_8bit)[0], expected, "8-bit MAC output")
    expectEqual(mac_8bit.len, 16, "8-bit MAC byte length")

    custom_text_encoding = [@minicrypt.Encode.encodeText8, @minicrypt.Encode.decodeText8]
    custom_mac = minicrypt.Poly1305.mac(key, message, custom_text_encoding, "base64")
    expectEqual(minicrypt.Encode.fromBase64(custom_mac)[0], expected, "Custom input encoding")

    expectEqual(typeof(minicrypt.Poly1305.mac(key, message, "unknown")), "error", "Reject unknown input encoding")
    expectEqual(typeof(minicrypt.Poly1305.mac(key, message, "8bit", "unknown")), "error", "Reject unknown output encoding")
    expectEqual(minicrypt.Poly1305.mac(key, "!", "base64"), false, "Reject malformed Base64 input")
end function
TEST "CHACHA20-POLY1305 - Poly1305.mac encodings", @test_chacha20poly1305_poly1305_encodings

test_chacha20poly1305_nonce_custom_encoding = function
    key = "171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c"
    nonce_hex = "010000000200000003000000"
    nonce = minicrypt.Encode.encodeHex(nonce_hex)[0]
    aad = "custom aad"
    plaintext = "custom encoded plaintext"

    ciphertext_from_list = minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, aad, "8bit", "base64", nonce)
    ciphertext_from_hex = minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, aad, "8bit", "base64", nonce_hex)
    decoded = minicrypt.Encode.fromBase64(ciphertext_from_hex)
    parts = minicrypt.ChaCha20Poly1305.splitMessage(decoded[0])
    expectEqual(parts[1], nonce, "Hex nonce is encoded as supplied")
    expectEqual(ciphertext_from_hex, ciphertext_from_list, "Hex and list nonces are equivalent")

    custom_text_encoding = [@minicrypt.Encode.encodeText8, @minicrypt.Encode.decodeText8]
    custom_ciphertext_encoding = [@minicrypt.Encode.fromBase64, @minicrypt.Encode.toBase64]
    ciphertext = minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, aad, custom_text_encoding, custom_ciphertext_encoding, nonce)
    expectEqual(
        minicrypt.ChaCha20Poly1305.decrypt(key, ciphertext, true, custom_text_encoding, custom_ciphertext_encoding),
        [plaintext, aad],
        "Custom encoder and decoder references"
    )
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, ciphertext, custom_ciphertext_encoding), "Custom ciphertext encoding verifies")
    expectEqual(minicrypt.ChaCha20Poly1305.getAAD(ciphertext, custom_text_encoding, custom_ciphertext_encoding), aad, "Custom encoding retrieves AAD")

    expectEqual(typeof(minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, aad, "unknown")), "error", "Reject unknown plaintext encoding")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, aad, "8bit", "unknown")), "error", "Reject unknown ciphertext encoding")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, ciphertext, true, "unknown")), "error", "Reject unknown plaintext decoding")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, ciphertext, true, "8bit", "unknown")), "error", "Reject unknown ciphertext decoding")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.verify(key, ciphertext, "unknown")), "error", "Reject unknown verification encoding")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.getAAD(ciphertext, "unknown")), "error", "Reject unknown AAD decoding")
end function
TEST "CHACHA20-POLY1305 - Nonce and custom encoding paths", @test_chacha20poly1305_nonce_custom_encoding

test_chacha20poly1305_nonce_split_errors = function
    key = minicrypt.Encode.encodeHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")[0]
    plaintext = minicrypt.Encode.encodeText8("nonce source")[0]
    nonce = minicrypt.ChaCha.getHedgedNonce(plaintext)
    expectEqual(nonce.len, 3, "Synthetic nonce has three words")
    for word in nonce
        expectTrue(word >= 0 and word < 4294967296, "Synthetic nonce word is 32-bit")
    end for

    key_hex = "171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c"
    ciphertext = minicrypt.ChaCha20Poly1305.encrypt(key_hex, "split", "", "8bit", "base64", [1, 2, 3])
    encoded = minicrypt.Encode.fromBase64(ciphertext)
    message = minicrypt.ChaCha20Poly1305.splitMessage(encoded[0])
    expectEqual(message[0].len, 4, "Message includes four tag words")
    expectEqual(message[1].len, 3, "Message includes three nonce words")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitMessage([0] * 10)), "error", "Reject message shorter than minimum")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitMessage([0] * 12)), "error", "Reject misaligned message")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decryptRaw(key, [1, 2, 3], [])), "error", "Propagate malformed AEAD from raw decrypt")
end function
TEST "CHACHA20-POLY1305 - Synthetic nonce and split errors", @test_chacha20poly1305_nonce_split_errors

test_chacha20poly1305_malformed_aead = function
    key = "171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c"
    aad = "Visible text"
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    ciphertext_b64 = minicrypt.ChaCha20Poly1305.encrypt(key, plaintext, aad)
    ciphertext = minicrypt.Encode.fromBase64(ciphertext_b64)[0]

    res = minicrypt.ChaCha20Poly1305.splitMessage(ciphertext)
    tag = res[0]
    nonce = res[1]
    aead = res[2]
    
    res = minicrypt.ChaCha20Poly1305.splitAEAD(aead)
    aad = res[0]
    aad_len = res[1]
    ciphertext = res[2]
    ciphertext_len = res[3]

    msg1 = minicrypt.Encode.toBase64(tag + nonce)
    msg2 = minicrypt.Encode.toBase64(tag + nonce + [4294967296, 4294967296, 4294967296, 4294967296])
    msg3 = minicrypt.Encode.toBase64(tag + nonce + aead + [0, 0, 0, 0])
    msg4 = minicrypt.Encode.toBase64(tag + nonce + aead[:-1])

    // add tag or nonce manipulation
    msg5 = ""
    msg6 = "h€h€"
    msg7 = ciphertext_b64[1:]
    msg8 = ciphertext_b64[:-1]
    msg9 = ciphertext_b64 + "==="
    msg10 = "=" + ciphertext_b64

    tampered_nonce = nonce[:]
    tampered_nonce[0] = tampered_nonce[0] + 1
    msg11 = minicrypt.Encode.toBase64(tag + tampered_nonce + aead)
    msg12 = minicrypt.Encode.toBase64(tag + [0,0,0] + aead)

    // These are checking that the program doesn't crash mostly
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg1 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg2 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg3 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg4 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg5 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg6 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg7 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg8 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg9 )), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg10)), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg11)), "error")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, msg12)), "error")

    // There are supposed to not crash and also to return false instead of null when something fails
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg1 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg2 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg3 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg4 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg5 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg6 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg7 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg8 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg9 ))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg10))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg11))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg12))
end function
TEST "CHACHA20-POLY1305 - Malformed AEAD", @test_chacha20poly1305_malformed_aead

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if