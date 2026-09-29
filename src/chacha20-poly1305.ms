// https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
// https://www.rfc-editor.org/info/rfc8439/
// 32 bit counter is enough for 256GB of data. Add this restriction explicitly

if not globals.hasIndex("minicrypt") then minicrypt = {}

import_code("./bigint.ms")
import_code("./encode.ms")

__scope = function //-------------


minicrypt.Poly1305 = {}
minicrypt.Poly1305.BigInt = new minicrypt.BigInt
minicrypt.Poly1305.BigInt.init(156, 26)

minicrypt.ChaCha = {}

minicrypt.ChaCha.ROUNDS = 20

minicrypt.ChaCha.POW2 = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888, 1099511627776, 2199023255552, 4398046511104, 8796093022208, 17592186044416, 35184372088832, 70368744177664, 140737488355328, 281474976710656, 562949953421312, 1125899906842624, 2251799813685248, 4503599627370496]

// Performs a xor on a and b, 32 bit numbers. Native xor only supports 31 bits D:
minicrypt.ChaCha.xor32 = function(a, b)
    a_btm   = a % 2147483648
    b_btm   = b % 2147483648
    xor_top = (a - a_btm != b - b_btm) * 2147483648
    return xor_top + bitXor(a_btm, b_btm)
end function

minicrypt.ChaCha.xorBlock = function(output, plaintext, key)
    if plaintext.len == 0 then return []
    for i in range(0, plaintext.len-1)
        output[i] = minicrypt.ChaCha.xor32(plaintext[i], key[i])
    end for
end function

// Rotate left, using faster arithmetic functions
minicrypt.ChaCha.ROTL = function(a, b)
    c = minicrypt.ChaCha.POW2[32-b]
    return ((a * minicrypt.ChaCha.POW2[b]) + (a / c - a % c / c)) % 4294967296
end function

minicrypt.ChaCha.QR = function(x, i, j, k, l)
    xor32 = @minicrypt.ChaCha.xor32
    ROTL = @minicrypt.ChaCha.ROTL
    x[i] = (x[i] + x[j]) % 4294967296
    x[l] = xor32(x[i], x[l])
    x[l] = ROTL(x[l], 16)

    x[k] = (x[k] + x[l]) % 4294967296
    x[j] = xor32(x[j], x[k])
    x[j] = ROTL(x[j], 12)

    x[i] = (x[i] + x[j]) % 4294967296
    x[l] = xor32(x[l], x[i])
    x[l] = ROTL(x[l], 8)

    x[k] = (x[k] + x[l]) % 4294967296
    x[j] = xor32(x[j], x[k])
    x[j] = ROTL(x[j], 7)
end function

// input, output = list of 16 numbers, 32-bit
minicrypt.ChaCha.chachaBlock = function(output, input)
    x = input[:]
    QR = @minicrypt.ChaCha.QR
    for i in range(0, minicrypt.ChaCha.ROUNDS-1, 2)
        // Odd round
        QR(x, 0, 4,  8, 12) // column 1
		QR(x, 1, 5,  9, 13) // column 2
		QR(x, 2, 6, 10, 14) // column 3
		QR(x, 3, 7, 11, 15) // column 4
		// Even round
		QR(x, 0, 5, 10, 15) // diagonal 1 (main diagonal)
		QR(x, 1, 6, 11, 12) // diagonal 2
		QR(x, 2, 7,  8, 13) // diagonal 3
		QR(x, 3, 4,  9, 14) // diagonal 4
    end for
    for i in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        output[i] = (x[i] + input[i]) % 4294967296
    end for
end function

// Sets ChaCha's internal state
// @param {list<number>} key       - secret key, list of 4 numbers, 32-bit 
// @param {list<number>} nonce     - random list of 3 numbers, 32-bit 
// @param {list<number>} plaintext - plaintext to be encrypted
// @param {number} counter         - leave as is
minicrypt.ChaCha.chacha = function(key, nonce, plaintext, byte_count, counter = 1)
    state = [1634760805,  857760878, 2036477234, 1797285236] + 
            key + 
            [counter] +
            nonce
    ciphertext = []
    key_stream = [0] * 16
    encrypted_block = [0] * 16

    i = -1
    if plaintext.len >= 16 then
        for i in range(0, floor(plaintext.len/16)-1)
            state[12] = counter + i
            minicrypt.ChaCha.chachaBlock(key_stream, state)
            block = plaintext[i*16:i*16+16]
            minicrypt.ChaCha.xorBlock(encrypted_block, block, key_stream)
            ciphertext  = ciphertext + encrypted_block
        end for
    end if
    if plaintext.len % 16 != 0 then
        i = i + 1
        state[12] = counter + i
        minicrypt.ChaCha.chachaBlock(key_stream, state)
        block = plaintext[i*16:plaintext.len]
        minicrypt.ChaCha.xorBlock(encrypted_block, block, key_stream)
        ciphertext = ciphertext + encrypted_block[:plaintext.len-i*16]
    end if
    byte_r = byte_count % 4
    if byte_r != 0 then
        ciphertext[-1] = ciphertext[-1] % minicrypt.ChaCha.POW2[byte_r * 8]
    end if
    return ciphertext
end function

// Using a hashed plaintext is necessary to ensure that if the plaintext is different, the nonce (read: keystream) is also different and can't be xor'd out
// The key is included into the hash to ensure that an attacker can't check if the plaintext is exactly equal to a guess
minicrypt.ChaCha.getSyntheticNonce = function(key, plaintext)
    s = plaintext + minicrypt.Encode.toBase64(key) + current_date + rnd
    nonce = [hash(s), hash("^"+s), hash(s+"$")]
    nonce[0] = nonce[0] % 4294967296
    nonce[1] = nonce[1] % 4294967296
    nonce[2] = nonce[2] % 4294967296
    if nonce[0] < 0 then nonce[0] = nonce[0] + 4294967296
    if nonce[1] < 0 then nonce[1] = nonce[1] + 4294967296
    if nonce[2] < 0 then nonce[2] = nonce[2] + 4294967296
    return nonce
end function

minicrypt.ChaCha.encrypt = function(key, plaintext, plaintext_encoding = "16bit", ciphertext_encoding = "base64", nonce = null, counter = 1)
    if typeof(@plaintext_encoding) == "list" then
        encoder = @plaintext_encoding[0]
    else if plaintext_encoding == "16bit" then
        encoder = @minicrypt.Encode.encodeText16
    else if plaintext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return null
    end if

    if typeof(@ciphertext_encoding) == "list" then
        decoder = @ciphertext_encoding[1]
    else if ciphertext_encoding == "base64" then
        decoder = @minicrypt.Encode.toBase64
    else if ciphertext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return null
    end if
    
    key_enc = minicrypt.Encode.hexToB32(key)

    res = encoder(plaintext)
    if res == null then return null
    plaintext_enc = res[0]
    plaintext_len = res[1]

    if typeof(nonce) == "string" then nonce = minicrypt.Encode.hexToB32(nonce)
    if nonce == null then nonce = minicrypt.ChaCha.getSyntheticNonce(key_enc, plaintext_enc)

    ciphertext_enc = minicrypt.ChaCha.chacha(key_enc, nonce, plaintext_enc, plaintext_len, counter)
    plaintext_len32 = plaintext_len % 4294967296
    enc = decoder(
        nonce +
        [plaintext_len32, (plaintext_len - plaintext_len32) / 4294967296] + 
        ciphertext_enc, 
        12 + 8 + plaintext_len)
    return enc
end function

minicrypt.ChaCha.decrypt = function(key, ciphertext, plaintext_encoding = "16bit", ciphertext_encoding = "base64", counter = 1)
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return null
    end if

    if typeof(@plaintext_encoding) == "list" then
        decoder = @plaintext_encoding[1]
    else if plaintext_encoding == "16bit" then
        decoder = @minicrypt.Encode.decodeText16
    else if plaintext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return null
    end if

    key_enc = minicrypt.Encode.hexToB32(key)

    res = encoder(ciphertext)
    if res == null then return null

    msg_enc = res[0]
    msg_len = res[1]
    if msg_enc.len < 5 then return null

    nonce_enc = msg_enc[:3]
    ciphertext_enc = msg_enc[5:]
    ciphertext_len = msg_enc[3] + msg_enc[4] * 4294967296
    if ciphertext_enc.len != ceil(ciphertext_len/4) then return null

    plaintext_enc = minicrypt.ChaCha.chacha(key_enc, nonce_enc, ciphertext_enc, ciphertext_len, counter)
    if plaintext_enc == null then return null
    plaintext_len = ciphertext_len

    plaintext = decoder(plaintext_enc, plaintext_len)
    return plaintext
end function

minicrypt.ChaCha.keygen = function(key, nonce)
    counter = 0
    state = [1634760805,  857760878, 2036477234, 1797285236] + 
            key + 
            [counter] +
            nonce
    block = [0] * 16
    minicrypt.ChaCha.chachaBlock(block, state)
    return block[:8]
end function

//------------------------------

// r is a list of 4 numbers, 32-bit
minicrypt.Poly1305.clampR = function(r)
    r[0] = r[0] % 268435456
    r[1] = (r[1] - r[1] % 4) % 268435456
    r[2] = (r[2] - r[2] % 4) % 268435456
    r[3] = (r[3] - r[3] % 4) % 268435456
    return r
end function

// https://www.rfc-editor.org/info/rfc8439/#section-2.5.1
// key should be a list of 8 numbers, 32-bit. Enough for 256 bits
// msg is serialized, list of 32-bit numbers.
minicrypt.Poly1305.macRaw = function(key, msg, byte_count)
    if msg.len == 0 then return null
    r = minicrypt.Poly1305.clampR(key[:4]) + [0]
    r = minicrypt.Encode.B32toB26(r)
    s = minicrypt.Encode.B32toB26(key[4:]) + [0]
    a = minicrypt.Poly1305.BigInt.zero
    p = [67108859, 67108863, 67108863, 67108863, 67108863, 0] //2^130-5
    for i in range(0, msg.len-1, 4)
        n = minicrypt.Encode.B32toB26(msg[i:i+4]) + [0]
        b = 128
        if i == msg.len-1 then
            n = n + [0] * (6 - n.len % 6)
            b = (byte_count % 16) * 8
            if b == 0 then b = 128
        end if
        bit = minicrypt.Poly1305.BigInt.pow2(b)
        n = minicrypt.Poly1305.BigInt.add(n, bit)
        a = minicrypt.Poly1305.BigInt.add(a, n)
        // a = (a * r) mod p
        a = minicrypt.Poly1305.BigInt.multP(a, r, 5, 5, p)
        
    end for
    a = minicrypt.Poly1305.BigInt.add(a, s)
    return minicrypt.Encode.B26toB32(a)
end function

minicrypt.Poly1305.mac = function(key, ciphertext, ciphertext_encoding = "base64")
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return null
    end if

    key_enc = minicrypt.Encode.hexToB32(key)
    
    res = encoder(ciphertext)
    if res == null then return false
    ciphertext_enc = res[0]
    ciphertext_len = res[1]

    verify = minicrypt.Poly1305.macRaw(key_enc, ciphertext_enc, ciphertext_len)
    if verify == null then return false
    return verify
end function

// ----------
minicrypt.ChaCha20Poly1305 = {}

minicrypt.ChaCha20Poly1305.AEAD = function(aad, aad_len, ciphertext, ciphertext_len)
    aad_len32 = aad_len % 4294967296
    ciphertext_len32 = ciphertext_len % 4294967296
    return  aad        + [0] * (4 - ceil(aad_len / 4) % 4) +
            ciphertext + [0] * (4 - ceil(ciphertext_len / 4) % 4) + 
            [aad_len32]        + [(aad_len - aad_len32) / 4294967296] +
            [ciphertext_len32] + [(ciphertext_len - ciphertext_len32) / 4294967296]
end function

// returns [aad, aad_len, ciphertext, ciphertext_len]
minicrypt.ChaCha20Poly1305.splitAEAD = function(aead)
    if aead.len < 4 then return null
    if aead.len % 4 != 0 then return null
    aad_len = aead[-4] + aead[-3] * 4294967296
    ciphertext_len = aead[-2] + aead[-1] * 4294967296
    aad_padded_len = ceil(aad_len/4) + (4 - ceil(aad_len / 4) % 4)
    ciphertext_padded_len = ceil(ciphertext_len/4) + (4 - ceil(ciphertext_len / 4) % 4)
    if aead.len != aad_padded_len + ciphertext_padded_len + 4 then return null
    aad = aead[:ceil(aad_len/4)]
    ciphertext = aead[aad_padded_len : aad_padded_len + ceil(ciphertext_len/4)]
    return [aad, aad_len, ciphertext, ciphertext_len]
end function

// returns [tag, nonce, aead]
minicrypt.ChaCha20Poly1305.splitMessage = function(msg)
    if msg.len < 11 or msg.len % 4 != 3 then return null
    return [msg[:4], msg[4:7], msg[7:]]
end function

//aad_len and ciphertext_len need to be safe integers, so the max size is smaller than in RFC 8439
minicrypt.ChaCha20Poly1305.encryptRaw = function(key, nonce, aad, aad_len, plaintext, plaintext_len)
    otk = minicrypt.ChaCha.keygen(key, nonce)
    ciphertext = minicrypt.ChaCha.chacha(key, nonce, plaintext, plaintext_len, 1)
    mac_data = minicrypt.ChaCha20Poly1305.AEAD(aad, aad_len, ciphertext, plaintext_len)
    tag = minicrypt.Poly1305.macRaw(otk, mac_data, mac_data.len * 4)
    return [mac_data, tag]
end function

minicrypt.ChaCha20Poly1305.decryptRaw = function(key, nonce, aead)
    res = minicrypt.ChaCha20Poly1305.splitAEAD(aead)
    if res == null then return null
    aad = res[0]
    aad_len = res[1]
    ciphertext = res[2]
    ciphertext_len = res[3]
    plaintext = minicrypt.ChaCha.chacha(key, nonce, ciphertext, ciphertext_len, 1)
    if plaintext == null then return null
    return [aad, aad_len, plaintext, ciphertext_len]
end function

minicrypt.ChaCha20Poly1305.verifyRaw = function(key, tag, nonce, aead)
    otk = minicrypt.ChaCha.keygen(key, nonce)
    actual_tag = minicrypt.Poly1305.macRaw(otk, aead, aead.len * 4)
    if actual_tag == null then return false
    return actual_tag == tag
end function

// if "encoding" is a custom function, it needs to take an arbitrary string and return
// a list of little-endian 32-bit integers, and the number of bytes.
minicrypt.ChaCha20Poly1305.encrypt = function(key, aad, plaintext, plaintext_encoding = "16bit", ciphertext_encoding = "base64", nonce = null)
    if typeof(@plaintext_encoding) == "list" then
        encoder = @plaintext_encoding[0]
    else if plaintext_encoding == "16bit" then
        encoder = @minicrypt.Encode.encodeText16
    else if plaintext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return null
    end if

    if typeof(@ciphertext_encoding) == "list" then
        decoder = @ciphertext_encoding[1]
    else if ciphertext_encoding == "base64" then
        decoder = @minicrypt.Encode.toBase64
    else if ciphertext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return null
    end if

    key_enc = minicrypt.Encode.hexToB32(key)
    
    enc = encoder(aad)
    if enc == null then return null
    aad_enc = enc[0]
    aad_len_bytes = enc[1]
    
    enc = encoder(plaintext)
    if enc == null then return null
    plaintext_enc = enc[0]
    plaintext_len_bytes = enc[1]

    if typeof(nonce) == "string" then nonce = minicrypt.Encode.hexToB32(key)
    if nonce == null then nonce = minicrypt.ChaCha.getSyntheticNonce(key_enc, plaintext_enc)
    
    enc = minicrypt.ChaCha20Poly1305.encryptRaw(key_enc, nonce, 
                                      aad_enc, aad_len_bytes, 
                                      plaintext_enc, plaintext_len_bytes)
    if enc == null then return null
    aead = enc[0]
    tag = enc[1]
    ciphertext = decoder(tag + nonce + aead, 16 + 12 + aead.len * 4)
    return ciphertext
end function

minicrypt.ChaCha20Poly1305.decrypt = function(key, ciphertext, plaintext_encoding = "16bit", ciphertext_encoding = "base64")
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return null
    end if

    if typeof(@plaintext_encoding) == "list" then
        decoder = @plaintext_encoding[1]
    else if plaintext_encoding == "16bit" then
        decoder = @minicrypt.Encode.decodeText16
    else if plaintext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return null
    end if

    key_enc = minicrypt.Encode.hexToB32(key)

    res = encoder(ciphertext)
    if res == null then return null
    ciphertext_enc = res[0]

    res = minicrypt.ChaCha20Poly1305.splitMessage(ciphertext_enc)
    if res == null then return null

    tag_enc = res[0]
    nonce_enc = res[1]
    aead_enc = res[2]

    verify = minicrypt.ChaCha20Poly1305.verifyRaw(key_enc, tag_enc, nonce_enc, aead_enc)
    if not verify then return null

    enc = minicrypt.ChaCha20Poly1305.decryptRaw(key_enc, nonce_enc, aead_enc)
    if enc == null then return null

    aad_enc = enc[0]
    aad_len_bytes = enc[1]
    plaintext_enc = enc[2]
    plaintext_len_bytes = enc[3]
    aad = decoder(aad_enc, aad_len_bytes)
    plaintext = decoder(plaintext_enc, plaintext_len_bytes)
    if aad == null or plaintext == null then return null

    return [aad, plaintext]
end function

minicrypt.ChaCha20Poly1305.verify = function(key, ciphertext, ciphertext_encoding = "base64")
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return null
    end if

    key_enc = minicrypt.Encode.hexToB32(key)
    
    res = encoder(ciphertext)
    if res == null then return false
    ciphertext_enc = res[0]

    res = minicrypt.ChaCha20Poly1305.splitMessage(ciphertext_enc)
    if res == null then return false

    tag_enc = res[0]
    nonce_enc = res[1]
    aead_enc = res[2]

    verify = minicrypt.ChaCha20Poly1305.verifyRaw(key_enc, tag_enc, nonce_enc, aead_enc)
    if verify == null then return false
    return verify
end function

minicrypt.ChaCha20Poly1305.getAad = function(ciphertext, plaintext_encoding = "16bit", ciphertext_encoding = "base64")
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return null
    end if

    if typeof(@plaintext_encoding) == "list" then
        decoder = @plaintext_encoding[1]
    else if plaintext_encoding == "16bit" then
        decoder = @minicrypt.Encode.decodeText16
    else if plaintext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return null
    end if

    res = encoder(ciphertext)
    if res == null then return null
    ciphertext_enc = res[0]

    res = minicrypt.ChaCha20Poly1305.splitAEAD(ciphertext_enc)
    if res == null then return null

    aad_enc = res[0]
    aad_len = res[1]
    aad = decoder(aad_enc, aad_len)
    return aad
end function

end function //-------------

if not minicrypt.hasIndex("ChaCha20Poly1305") then __scope()
globals.remove("__scope")