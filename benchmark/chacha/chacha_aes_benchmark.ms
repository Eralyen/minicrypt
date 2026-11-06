import_code("AES128.src")
import_code("../../minicrypt.ms")

cc = minicrypt.ChaCha
c20p = minicrypt.ChaCha20Poly1305

ROUNDS = range(500, 10000, 500)
REPEATS = 5
CHAR = "A"

PERFORMANCE = {
    "ChaCha8-8bit":         [0] * ROUNDS.len,
    "ChaCha8":              [0] * ROUNDS.len,
    "ChaCha20":             [0] * ROUNDS.len,
    "ChaCha20-Poly1305":    [0] * ROUNDS.len,
    "AES-128":              [0] * ROUNDS.len,
}

key_AES    = "foobar1234567890"
key_chacha = "666f6f62617231323334353637383930666f6f62617231323334353637383930" // same value as above, but in hex and repeated 2x
key_chacha_bytes = minicrypt.Encode.encodeHex(key_chacha)[0]
nonce_chacha = [0, 0, 0]

printPerformance = function(PERFORMANCE, i)
    print "Results:"
    print
    s = "CHARACTERS " + PERFORMANCE.indexes.join(" ") + char(10)
    for r in range(0, i-1)
        s = s + ROUNDS[r]
        for idx in PERFORMANCE.indexes
            s = s + " " + str(PERFORMANCE[idx][r])[:5]
        end for
        s = s + char(10)
    end for
    print format_columns(s)
    print
    print "Results in CSV format:"
    print
    print "CHARACTERS," + PERFORMANCE.indexes.join(",")
    for r in range(0, i-1)
        s = ROUNDS[r]
        for idx in PERFORMANCE.indexes
            s = s + "," + PERFORMANCE[idx][r]
        end for
        print s
    end for

    print
    print "Total runtime: " + time + "s"
end function

for r in range(0, ROUNDS.len-1)
    length = ROUNDS[r]
    print "Encryption of " + REPEATS + " strings of length " + length
    plaintext = CHAR * length
    plaintext_8bit = minicrypt.Encode.encodeText8(plaintext)
    plaintext_16bit = minicrypt.Encode.encodeText16(plaintext)

    // ChaCha8-8bit
    start = time
    for i in range(0, REPEATS-1)
        ciphertext = cc.chacha(key_chacha_bytes, nonce_chacha, plaintext_8bit[0], plaintext_8bit[1], 1, 8)
        decrypted = cc.chacha(key_chacha_bytes, nonce_chacha, ciphertext, plaintext_8bit[1], 1, 8)
    end for
    t = time - start
    PERFORMANCE["ChaCha8-8bit"][r] = t / REPEATS

    // ChaCha8
    start = time
    for i in range(0, REPEATS-1)
        ciphertext = cc.chacha(key_chacha_bytes, nonce_chacha, plaintext_16bit[0], plaintext_16bit[1], 1, 8)
        decrypted = cc.chacha(key_chacha_bytes, nonce_chacha, ciphertext, plaintext_16bit[1], 1, 8)
    end for
    t = time - start
    PERFORMANCE["ChaCha8"][r] = t / REPEATS
    
    // ChaCha20
    start = time
    for i in range(0, REPEATS-1)
        ciphertext = cc.chacha(key_chacha_bytes, nonce_chacha, plaintext_16bit[0], plaintext_16bit[1], 1, 20)
        decrypted = cc.chacha(key_chacha_bytes, nonce_chacha, ciphertext, plaintext_16bit[1], 1, 20)
    end for
    t = time - start
    PERFORMANCE["ChaCha20"][r] = t / REPEATS

    // ChaCha20-Poly1305
    start = time
    for i in range(0, REPEATS-1)
        encrypted = c20p.encrypt(key_chacha_bytes, nonce_chacha, [], 0, plaintext_16bit[0], plaintext_16bit[1])
        verified = c20p.verify(key_chacha_bytes, encrypted[1], nonce_chacha, encrypted[0])
        decrypted = c20p.decrypt(key_chacha_bytes, nonce_chacha, encrypted[0])
    end for
    t = time - start
    PERFORMANCE["ChaCha20-Poly1305"][r] = t / REPEATS

    // AES-128
    start = time
    for i in range(0, REPEATS-1)
        ciphertext = AES128("encrypt", key_AES, plaintext)
        deciphered = AES128("decrypt", key_AES, ciphertext)
    end for
    t = time - start
    PERFORMANCE["AES-128"][r] = t / REPEATS

    clear_screen
    printPerformance(PERFORMANCE, r+1)
    print
end for