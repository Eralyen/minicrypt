globals.isGH = true
import_code("./MiniTest.src")
import_code("../src/chacha20-poly1305.ms")
import_code("../src/encode.ms")

TEST "ChaCha.chachaBlock", function
    //TODO: test edge cases
end function

TEST "ChaCha.encrypt - ChaCha.decrypt", function
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

TEST "ChaCha20Poly1305.*Raw", function
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
    aead_tampered[2] = aead_tampered[2] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verifyRaw(key, mac, nonce, aead_tampered), "Rejection of tampered AEAD")

    res = minicrypt.ChaCha20Poly1305.decryptRaw(key, nonce, aead)
    deciphered = res[2]
    expectEqual(deciphered, plaintext, "Deciphered text matches")
end function

TEST "Malformed AEAD", function
    key = "171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c"
    aad = "Visible text"
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    ciphertext_b64 = minicrypt.ChaCha20Poly1305.encrypt(key, aad, plaintext)
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

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if