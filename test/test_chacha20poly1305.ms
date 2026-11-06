globals.isGH = true
import_code("./MiniTest/MiniTest.src")
import_code("../src/chacha20-poly1305.ms")
import_code("../src/encode.ms")

test_chacha20poly1305_cipher_and_aead = function
    key = minicrypt.Encode.hexBytesToB32("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
    nonce = minicrypt.Encode.hexBytesToB32("00:00:00:00:00:00:00:4a:00:00:00:00")
    counter = 1
    plaintexts = [
        minicrypt.Encode.encodeText8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
        minicrypt.Encode.encodeText16("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
        minicrypt.Encode.encodeText16("Plaintext length checks exercise the final partial word."),
        minicrypt.Encode.encodeText16("Odd"),
    ]

    for plaintext in plaintexts
        ciphertext = minicrypt.ChaCha.chacha(key, nonce, plaintext[0], plaintext[1], counter)
        deciphered = minicrypt.ChaCha.chacha(key, nonce, ciphertext, plaintext[1], counter)
        expectEqual(ciphertext.len, ceil(plaintext[1] / 4), "Ciphertext word count")
        expectEqual(deciphered, plaintext[0], "Successive encryption and decryption")
    end for
    plaintext = minicrypt.Encode.encodeText8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")[0]
    plaintext_len = 114
    aad = minicrypt.Encode.hexBytesToB32("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7")
    aad_len = 12
    key = minicrypt.Encode.hexBytesToB32("80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f")
    IV = "40:41:42:43:44:45:46:47"
    constant = "07:00:00:00"
    nonce = minicrypt.Encode.hexBytesToB32(constant + ":" + IV)
    counter = 1
    res = minicrypt.ChaCha20Poly1305.encrypt(key, nonce, aad, aad_len, plaintext, plaintext_len)
    aead = res[0]
    mac = res[1]
    aead_expected = minicrypt.Encode.hexBytesToB32("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7:00:00:00:00:d3:1a:8d:34:64:8e:60:db:7b:86:af:bc:53:ef:7e:c2:a4:ad:ed:51:29:6e:08:fe:a9:e2:b5:a7:36:ee:62:d6:3d:be:a4:5e:8c:a9:67:12:82:fa:fb:69:da:92:72:8b:1a:71:de:0a:9e:06:0b:29:05:d6:a5:b6:7e:cd:3b:36:92:dd:bd:7f:2d:77:8b:8c:98:03:ae:e3:28:09:1b:58:fa:b3:24:e4:fa:d6:75:94:55:85:80:8b:48:31:d7:bc:3f:f4:de:f0:8e:4b:7a:9d:e5:76:d2:65:86:ce:c6:4b:61:16:00:00:00:00:00:00:00:00:00:00:00:00:00:00:0c:00:00:00:00:00:00:00:72:00:00:00:00:00:00:00")
    
    expectEqual(aead, aead_expected, "AEAD")
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, mac, nonce, aead), "Verification of authentic AEAD")

    aead_tampered = aead[:]
    aead_tampered[0] = aead_tampered[0] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, mac, nonce, aead_tampered), "Rejection of tampered AAD")

    aead_tampered = aead[:]
    aead_tampered[2] = aead_tampered[2] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, mac, nonce, aead_tampered), "Rejection of tampered AEAD")

    res = minicrypt.ChaCha20Poly1305.decrypt(key, nonce, aead)
    deciphered = res[2]
    expectEqual(deciphered, plaintext, "Deciphered text matches")
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
TEST "CHACHA20-POLY1305 - ChaCha, AEAD, and boundaries", @test_chacha20poly1305_cipher_and_aead

test_chacha20poly1305_auth_and_byte_list_formats = function
    key = minicrypt.Encode.encodeHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")[0]
    nonce = [1, 2, 3]
    aad = minicrypt.Encode.encodeText16("A" + char(0) + char(233))
    plaintext = minicrypt.Encode.encodeText16("B" + char(0) + char(233) + char(65535))

    result = minicrypt.ChaCha20Poly1305.encrypt(key, nonce, aad[0], aad[1], plaintext[0], plaintext[1])
    aead = result[0]
    tag = result[1]
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, tag, nonce, aead), "AEAD authenticates")

    decrypted = minicrypt.ChaCha20Poly1305.decrypt(key, nonce, aead)
    expectEqual(decrypted[0], aad[0], "Decryption recovers AAD")
    expectEqual(decrypted[1], aad[1], "Decryption recovers AAD byte count")
    expectEqual(decrypted[2], plaintext[0], "Decryption recovers plaintext")
    expectEqual(decrypted[3], plaintext[1], "Decryption recovers plaintext byte count")

    tampered_aead = aead[:]
    tampered_aead[0] = tampered_aead[0] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, tag, nonce, tampered_aead), "Reject changed AAD")

    tampered_tag = tag[:]
    tampered_tag[0] = (tampered_tag[0] + 1) % 4294967296
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, tampered_tag, nonce, aead), "Reject changed authentication tag")
    wrong_key = minicrypt.Encode.encodeHex("0000000000000000000000000000000000000000000000000000000000000000")[0]
    expectFalse(minicrypt.ChaCha20Poly1305.verify(wrong_key, tag, nonce, aead), "Reject wrong key")

    plaintext = minicrypt.Encode.encodeText8("8-bit plaintext")
    result = minicrypt.ChaCha20Poly1305.encrypt(key, [4, 5, 6], [], 0, plaintext[0], plaintext[1])
    decrypted = minicrypt.ChaCha20Poly1305.decrypt(key, [4, 5, 6], result[0])
    expectEqual(decrypted[0], [], "Empty AAD round trip")
    expectEqual(decrypted[2], plaintext[0], "8-bit plaintext round trip")
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, result[1], [4, 5, 6], result[0]), "8-bit message authenticates")

    for plaintext_len in [1, 15, 16, 17, 63, 64, 65]
        plaintext = minicrypt.Encode.encodeText8("x" * plaintext_len)
        aad = minicrypt.Encode.encodeText8("boundary")
        nonce = [plaintext_len, 10, 11]
        result = minicrypt.ChaCha20Poly1305.encrypt(key, nonce, aad[0], aad[1], plaintext[0], plaintext[1])
        decrypted = minicrypt.ChaCha20Poly1305.decrypt(key, nonce, result[0])
        expectEqual(decrypted[0], aad[0], "AAD round trip at plaintext byte length " + str(plaintext_len))
        expectEqual(decrypted[2], plaintext[0], "Plaintext round trip at byte length " + str(plaintext_len))
        expectTrue(minicrypt.ChaCha20Poly1305.verify(key, result[1], nonce, result[0]), "Authenticates plaintext byte length " + str(plaintext_len))
    end for

    result = minicrypt.ChaCha20Poly1305.encrypt(key, [7, 8, 9], [], 0, [], 0)
    decrypted = minicrypt.ChaCha20Poly1305.decrypt(key, [7, 8, 9], result[0])
    expectEqual(decrypted[0], [], "Empty AAD round trip")
    expectEqual(decrypted[2], [], "Empty plaintext round trip")
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, result[1], [7, 8, 9], result[0]), "Empty message authenticates")
    key = minicrypt.Encode.hexBytesToB32("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b")
    message = minicrypt.Encode.encodeText8("Cryptographic Forum Research Group")
    tag = minicrypt.Poly1305.mac(key, message[0], message[1])
    expectEqual(tag.len, 4, "Poly1305 tag has four 32-bit words")
    expected = minicrypt.Encode.hexBytesToB32("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")
    expectEqual(tag, expected, "RFC 8439 Poly1305 tag")

    decoded_key = minicrypt.Encode.encodeHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")[0]
    expectEqual(decoded_key, key, "Hex key converts to a byte list")
    key = minicrypt.Encode.encodeHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")[0]
    nonce_hex = "010000000200000003000000"
    nonce = minicrypt.Encode.encodeHex(nonce_hex)[0]
    aad = minicrypt.Encode.encodeText8("custom aad")
    plaintext = minicrypt.Encode.encodeText8("custom encoded plaintext")

    result = minicrypt.ChaCha20Poly1305.encrypt(key, nonce, aad[0], aad[1], plaintext[0], plaintext[1])
    decrypted = minicrypt.ChaCha20Poly1305.decrypt(key, nonce, result[0])
    message = result[1] + nonce + result[0]
    parts = minicrypt.ChaCha20Poly1305.splitMessage(message)
    expectEqual(parts[0], result[1], "Message includes the authentication tag")
    expectEqual(parts[1], nonce, "Message includes the nonce")
    expectEqual(parts[2], result[0], "Message includes the AEAD")
    expectEqual(decrypted[0], aad[0], "AAD round trip")
    expectEqual(decrypted[2], plaintext[0], "Plaintext round trip")
    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, result[1], nonce, result[0]), "Message verifies")
end function
TEST "CHACHA20-POLY1305 - Authentication and byte-list formats", @test_chacha20poly1305_auth_and_byte_list_formats

test_chacha20poly1305_input_validation = function
    key = minicrypt.Encode.encodeHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")[0]
    plaintext = minicrypt.Encode.encodeText8("nonce source")[0]
    nonce = minicrypt.ChaCha.getHedgedNonce(plaintext)
    expectEqual(nonce.len, 3, "Synthetic nonce has three words")
    for word in nonce
        expectTrue(word >= 0 and word < 4294967296, "Synthetic nonce word is 32-bit")
    end for

    nonce = [1, 2, 3]
    key = minicrypt.Encode.encodeHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")[0]
    plaintext = minicrypt.Encode.encodeText8("split")
    result = minicrypt.ChaCha20Poly1305.encrypt(key, nonce, [], 0, plaintext[0], plaintext[1])
    message = minicrypt.ChaCha20Poly1305.splitMessage(result[1] + nonce + result[0])
    expectEqual(message[0].len, 4, "Message includes four tag words")
    expectEqual(message[1].len, 3, "Message includes three nonce words")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitMessage([0] * 10)), "error", "Reject message shorter than minimum")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitMessage([0] * 12)), "error", "Reject misaligned message")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, [1, 2, 3], [])), "error", "Propagate malformed AEAD from decrypt")
    key = minicrypt.Encode.encodeHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")[0]
    nonce = [1, 2, 3]
    aad = minicrypt.Encode.encodeText8("Visible text")
    plaintext = minicrypt.Encode.encodeText8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
    result = minicrypt.ChaCha20Poly1305.encrypt(key, nonce, aad[0], aad[1], plaintext[0], plaintext[1])
    tag = result[1]
    aead = result[0]

    expectTrue(minicrypt.ChaCha20Poly1305.verify(key, tag, nonce, aead), "Valid AEAD verifies")

    tampered_tag = tag[:]
    tampered_tag[0] = tampered_tag[0] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, tampered_tag, nonce, aead), "Reject changed tag")

    tampered_nonce = nonce[:]
    tampered_nonce[0] = tampered_nonce[0] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, tag, tampered_nonce, aead), "Reject changed nonce")

    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitMessage([0] * 10)), "error", "Reject short message")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitMessage([0] * 12)), "error", "Reject misaligned message")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitAEAD([])), "error", "Reject short AEAD")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitAEAD([0, 0, 0])), "error", "Reject unpadded AEAD")

    malformed_aead = aead[:]
    malformed_aead[-2] = malformed_aead[-2] + 16
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.splitAEAD(malformed_aead)), "error", "Reject inconsistent AEAD length")
    expectEqual(typeof(minicrypt.ChaCha20Poly1305.decrypt(key, nonce, malformed_aead)), "error", "Reject malformed AEAD before decrypting")
end function
TEST "CHACHA20-POLY1305 - Input validation", @test_chacha20poly1305_input_validation

test_chacha8poly1305 = function
    key = minicrypt.Encode.encodeHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")[0]
    nonce = [1, 2, 3]
    aad = minicrypt.Encode.encodeText8("ChaCha8 AAD")
    plaintext = minicrypt.Encode.encodeText8("ChaCha8 Poly1305 round-trip test")

    chacha8_result = minicrypt.ChaCha8Poly1305.encrypt(key, nonce, aad[0], aad[1], plaintext[0], plaintext[1])
    chacha20_result = minicrypt.ChaCha20Poly1305.encrypt(key, nonce, aad[0], aad[1], plaintext[0], plaintext[1])

    expectTrue(minicrypt.ChaCha8Poly1305.verify(key, chacha8_result[1], nonce, chacha8_result[0]), "ChaCha8-Poly1305 authenticates its result")
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, chacha8_result[1], nonce, chacha8_result[0]), "ChaCha20-Poly1305 rejects the ChaCha8 tag")
    expectTrue(chacha8_result[0] != chacha20_result[0], "ChaCha8 ciphertext differs from ChaCha20")

    decrypted = minicrypt.ChaCha8Poly1305.decrypt(key, nonce, chacha8_result[0])
    expectEqual(decrypted[0], aad[0], "ChaCha8-Poly1305 recovers AAD")
    expectEqual(decrypted[2], plaintext[0], "ChaCha8-Poly1305 recovers plaintext")
end function
TEST "CHACHA8-POLY1305 - Authentication and round-trip", @test_chacha8poly1305

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if