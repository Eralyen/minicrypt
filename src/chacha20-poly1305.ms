// ChaCha20 is a symmetric stream cipher that is much faster than the more commonly used AES when hardware acceleration isn't available.
// It's often combined with Poly1305, a keyed hash function that can be used to provide message authentication.
// https://en.wikipedia.org/wiki/ChaCha20-Poly1305
//
// This implementation provides both algorithms separately, as well as combined together. I followed this RFC specification:
// https://www.rfc-editor.org/info/rfc8439/

if not globals.hasIndex("minicrypt") then minicrypt = {}

import_code("./blake3.ms")
import_code("./math.ms")
import_code("./encode.ms")
import_code("./error.ms")

__scope = function //-------------
locals.minicrypt = minicrypt

Math = minicrypt.Math
xor32 = @Math.xor32
ROTL = @Math.rotl

BLAKE3 = minicrypt.BLAKE3
Encode = minicrypt.Encode
Error = @minicrypt.Error

minicrypt.ChaCha = {}
minicrypt.Poly1305 = {}
minicrypt.ChaCha20Poly1305 = {}
minicrypt.ChaCha8Poly1305 = {}

ChaCha = minicrypt.ChaCha
Poly1305 = minicrypt.Poly1305
ChaCha20Poly1305 = minicrypt.ChaCha20Poly1305
ChaCha8Poly1305 = minicrypt.ChaCha8Poly1305

// Calculates 'output = plaintext ^ key'. 'output', 'plaintext' and 'key' should be equally-sized lists of 32-bit integers. For performance reasons, no checks are done to verify the inputs.
// @param {list<number>} output    - output list. Should be initialized as [0] * 16 or recycled
// @param {list<number>} plaintext - list of 0-16 32-bit integers
// @param {list<number>} key       - list of 0-16 32-bit integers
// @returns {null}
ChaCha.xorBlock = function(output, plaintext, key)
    for i in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15][:plaintext.len]
        output[i] = Math.xor32(plaintext[i], key[i])
    end for
end function

// ChaCha quarter round, an ARX operation. Modifies the ChaCha state directly.
// Four quarter rounds make a full ChaCha round.
// @param {list<number>} x - the ChaCha state, a list of 16 32-bit integers
// @param {number}       i - the first  index
// @param {number}       j - the second index
// @param {number}       k - the third  index
// @param {number}       l - the fourth index
// @returns {null}
ChaCha.QR = function(x, i, j, k, l)
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
QR = @ChaCha.QR

// Takes a starting ChaCha state and performs the specified even number of ChaCha rounds on it, then adds it to the original state again.
// @param {list<number>} output - final state. Should be initialized as [0] * 16 or recycled
// @param {list<number>} input  - initial state, a list of 16 32-bit integers.
// @param {number}       rounds - (optional) even number of ChaCha rounds, default 8
// @returns {null}
ChaCha.chachaBlock = function(output, input, rounds = 8)
    x = input[:]
    QR = @ChaCha.QR
    for i in range(0, rounds-1, 2)
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

// Creates the correct ChaCha state from the key, nonce, and counter.
// @params {list<number>}  key     - a list of 8 32-bit integers
// @params {list<number>}  nonce   - a list of 3 32-bit integers
// @params {number}        counter - a 32-bit number
// @returns {list<number>}         - the assembled ChaCha state, a list of 16 32-bit integers
ChaCha.assembleState = function(key, nonce, counter)
    return [1634760805, 857760878, 2036477234, 1797285236] +
           key +
           [counter] +
           nonce
end function

// Generates a keystream from the provided key.
// @params {list<number>}  key        - a list of 8 32-bit integers. The secret key
// @params {list<number>}  nonce      - a list of 3 32-bit integers. A unique value
// @param {number}         byte_count - a 32-bit integer. The desired length of the bytestream
// @param {number}         [counter]  - a 32-bit integer. The starting ChaCha counter, is used to ensure that (counter + nonce) is unique for each block
// @param {number}         [rounds]   - an even number of ChaCha rounds, default 8
// @returns {list<number>}            - a list of 32-bit integers, holding 'byte_count' bytes
ChaCha.keystream = function(key, nonce, byte_count, counter = 1, rounds = 8)
    if byte_count == 0 then return []
    p = [4294967296, 256, 65536, 16777216]
    r = byte_count % 4
    words = (byte_count - r) / 4 + (r > 0)
    state = ChaCha.assembleState(key, nonce, counter)
    key_stream = []
    ks = [0] * 16
    i = 0
    while i*16 < words
        state[12] = counter + i
        ChaCha.chachaBlock(ks, state, rounds)
        key_stream = key_stream + ks
        i = i + 1
    end while
    key_stream = key_stream[:words]
    key_stream[-1] = key_stream[-1] % p[r]
    return key_stream
end function

// Encrypts or decrypts an encoded message using the ChaCha algorithm.
// @params {list<number>}  key        - a list of 8 32-bit integers. The secret key
// @params {list<number>}  nonce      - a list of 3 32-bit integers. A unique value
// @param {list<number>}   input      - a list of 32-bit integers. The input to be encrypted/decrypted
// @param {number}         byte_count - a 32-bit integer. The length of 'input' in bytes
// @param {number}         [counter]  - a 32-bit integer. The starting ChaCha counter, is used to ensure that (counter + nonce) is unique for each block
// @param {number}         [rounds]   - an even number of ChaCha rounds, default 8
// @returns {list<number>}            - a list of 32-bit integers, the same byte count as 'input'
ChaCha.chacha = function(key, nonce, input, byte_count, counter = 1, rounds = 8)
    state = ChaCha.assembleState(key, nonce, counter)
    output = []
    key_stream = [0] * 16
    encrypted_block = [0] * 16
    i = -1
    if input.len >= 16 then
        for i in range(0, floor(input.len/16)-1)
            state[12] = counter + i
            ChaCha.chachaBlock(key_stream, state, rounds)
            block = input[i*16:i*16+16]
            ChaCha.xorBlock(encrypted_block, block, key_stream)
            output  = output + encrypted_block
        end for
    end if
    if input.len % 16 != 0 then
        i = i + 1
        state[12] = counter + i
        ChaCha.chachaBlock(key_stream, state, rounds)
        block = input[i*16:input.len]
        ChaCha.xorBlock(encrypted_block, block, key_stream)
        output = output + encrypted_block[:input.len-i*16]
    end if
    byte_r = byte_count % 4
    if byte_r != 0 then
        output[-1] = output[-1] % Math.POW2[byte_r * 8]
    end if
    return output
end function

// Creates a safe nonce (partially random, partially derived from the plaintext) if the user is unable to provide one with this key property: if plaintext1 -> nonce1 and plaintext2 -> nonce2, then if plaintext1 != plaintext2 then it's extremely unlikely that nonce1 == nonce2
// @params {list<number>}  plaintext - a list of 32-bit integers.
// @returns {list<number>}           - a list of 3 32-bit integers
ChaCha.getHedgedNonce = function(plaintext)
    hash_state = BLAKE3.startDeriveKey(plaintext, plaintext.len*4)
    BLAKE3.updateHash(hash_state, [floor(rnd * 4294967296)], 4)
    nonce = BLAKE3.finalizeHash(hash_state, 3)
    return nonce
end function

// addition of two numbers as lists of 17 bytes. the result is stored in a
Poly1305.add = function(a, b)
    u = 0
    for i in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        u = u + a[i] + b[i]
        a[i] = u % 256
        u = (u - a[i]) / 256
    end for
    a[16] = (u + a[16] + b[16]) % 256
end function

// Given a secret key and an encoded message of any size, computes a 128 bit fingerprint of that message.
// @param {list<number>}   key        - list of 8 32-bit integers
// @param {list<number>}   msg        - list of 32-bit integers
// @param {number}         byte_count - length of the message in bytes
// @returns {list<number>}            - list of 4 32-bit integers
Poly1305.mac = function(key, msg, byte_count)
    k = []
    for i in [0,1,2,3,4,5,6,7]
        wk = key[i]
        newk = [0] * 4
        for j in [0,1,2]
            newk[j] = wk % 256
            wk = (wk - newk[j]) / 256
        end for
        newk[3] = wk
        k = k + newk
    end for
    r = k[:16] + [0]
    s = k[16:] + [0]
    // Clamp the 'r' value
    r[3] = r[3] % 16
    r[4] = r[4] - r[4] % 4
    r[7] = r[7] % 16
    r[8] = r[8] - r[8] % 4
    r[11] = r[11] % 16
    r[12] = r[12] - r[12] % 4
    r[15] = r[15] % 16
    h = [0] * 17
    minusp = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252]
    m = []
    for w in msg
        newm = [0] * 4
        for j in [0,1,2]
            newm[j] = w % 256
            w = (w - newm[j]) / 256
        end for
        newm[3] = w
        m = m + newm
    end for
    m = m[:byte_count]
    if m.len > 0 then
        x = [0] * 17
        for mpos in range(0, m.len-1, 16)
            c = m[mpos:mpos+16]
            c = c + [1] + [0] * (16-c.len)
            Poly1305.add(h, c)
            for i in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
                x[i] = 0
                for j in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
                    if j <= i then
                        x[i] = x[i] + h[j] * r[i - j]
                    else
                        x[i] = x[i] + h[j] * (320 * r[i + 17 - j])
                    end if
                end for
            end for
            u = 0
            for i in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
                u = u + x[i]
                h[i] = u % 256
                u = (u - h[i]) / 256
            end for
            u = u + x[16]
            h[16] = u % 4;
            u = 5 * ((u - h[16]) / 4)
            for i in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
                u = u + h[i]
                h[i] = u % 256
                u = (u - h[i]) / 256
            end for
            u = u + h[16]
            h[16] = u
        end for
    end if
    g = h[:]
    Poly1305.add(h, minusp)
    s = h[16] >= 128
    c = [0] * 17
    for i in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        h[i] = h[i] + s * (g[i] - h[i])
        c[i] = k[i + 16]
    end for
    h[16] = h[16] + s * (g[16] - h[16])
    Poly1305.add(h, c)
    mac = [0, 0, 0, 0]
    for i in [0, 1, 2, 3]
        j = i*4
        mac[i] = h[j] + h[j+1] * 256 + h[j+2] * 65536 + h[j+3] * 16777216
    end for
    return mac
end function

// ----------

// Generates a one-time key for Poly1305 using ChaCha
// Uses 8 rounds of ChaCha
// @param {list<number>}   key   - a list of 8 32-bit integers
// @param {list<number>}   nonce - a list of 3 32-bit integers
// @returns {list<number>}       - a list of 8 32-bit integers
ChaCha8Poly1305.keygen = function(key, nonce)
    state = ChaCha.assembleState(key, nonce, 0)
    block = [0] * 16
    ChaCha.chachaBlock(block, state, 8)
    return block[:8]
end function

// Assembles the ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) from its constituent parts
// @param {list<number>}   aad            - a list of 32-bit integers, any length
// @param {number}         aad_len        - the length of the aad in bytes
// @param {list<number>}   ciphertext     - a list of 32-bit integers, any length
// @param {number}         ciphertext_len - the length of the ciphertext in bytes
// @returns {list<number>}                - a list of 32-bit integers
ChaCha8Poly1305.AEAD = function(aad, aad_len, ciphertext, ciphertext_len)
    aad_len32 = aad_len % 4294967296
    ciphertext_len32 = ciphertext_len % 4294967296
    return  aad        + [0] * (ceil(aad_len / 16) * 4 - ceil(aad_len / 4)) +
            ciphertext + [0] * (ceil(ciphertext_len / 16) * 4 - ceil(ciphertext_len / 4)) +
            [aad_len32]        + [(aad_len - aad_len32) / 4294967296] +
            [ciphertext_len32] + [(ciphertext_len - ciphertext_len32) / 4294967296]
end function

// Splits the AEAD into its components. Returns [aad , aad_len, ciphertext, ciphertext_len] if the AEAD is well-formed, or an error otherwise.
// @description The AAD and ciphertext can be any length
// @param {list<number>} aead - a list of 32-bit integers
// @returns {list | error}    - if not an error, it returns [aad , aad_len, ciphertext, ciphertext_len] -> [list<number>, number, list<number>, number]
ChaCha8Poly1305.splitAEAD = function(aead)
    if aead.len < 4 then return Error("ChaCha20Poly1305.splitAEAD", "short_aead")
    if aead.len % 4 != 0 then return Error("ChaCha20Poly1305.splitAEAD", "unpadded_aead")
    aad_len = aead[-4] + aead[-3] * 4294967296
    ciphertext_len = aead[-2] + aead[-1] * 4294967296
    aad_padded_len = ceil(aad_len / 16) * 4
    ciphertext_padded_len = ceil(ciphertext_len / 16) * 4
    if aead.len != aad_padded_len + ciphertext_padded_len + 4 then return Error("ChaCha20Poly1305.splitAEAD", "length_mismatch")
    aad = aead[:ceil(aad_len/4)]
    ciphertext = aead[aad_padded_len : aad_padded_len + ceil(ciphertext_len/4)]
    return [aad, aad_len, ciphertext, ciphertext_len]
end function

// Encrypts and authenticates the plaintext and aad using the provided key and nonce. Returns [aead, tag]
// @description The AEAD is a list of 32-bit integers of any length depending on the aad and plaintext.
// @description The tag is a list of 4 32-bit integers, and is the Poly1305 message authentication code computed on the AEAD post-encryption.
// @param {list<number>} key           - a list of 8 32-bit integers
// @param {list<number>} nonce         - a list of 3 32-bit integers
// @param {list<number>} aad           - a list of 32-bit integers, any size
// @param {number}       aad_len       - the length of 'aad' in bytes
// @param {list<number>} plaintext     - a list of 32-bit integers, any size
// @param {number}       plaintext_len - the length of 'plaintext' in bytes
// @returns {list}                     - [aead, tag] -> [list<number>, list<number>]
ChaCha8Poly1305.encrypt = function(key, nonce, aad, aad_len, plaintext, plaintext_len)
    otk = ChaCha8Poly1305.keygen(key, nonce)
    ciphertext = ChaCha.chacha(key, nonce, plaintext, plaintext_len, 1, 8)
    aead = ChaCha8Poly1305.AEAD(aad, aad_len, ciphertext, plaintext_len)
    tag = Poly1305.mac(otk, aead, aead.len * 4)
    return [aead, tag]
end function

// Decrypts the AEAD WITHOUT AUTHENTICATING IT using the provided key and nonce. Returns [aad, aad_len, plaintext, plaintext_len]. It's very important to authenticate the AEAD before calling this method.
// @description The aad is a list of 32-bit integers of any length.
// @description The plaintext is a list of 32-bit integers of any length.
// @param {list<number>} key           - a list of 8 32-bit integers
// @param {list<number>} nonce         - a list of 3 32-bit integers
// @param {list<number>} aad           - a list of 32-bit integers, any size
// @returns {list | error}             - [aad, aad_len, plaintext, plaintext_len] -> [list<number>, number, list<number>, number] or an error
ChaCha8Poly1305.decrypt = function(key, nonce, aead)
    res = ChaCha8Poly1305.splitAEAD(aead)
    if typeof(res) == "error" then return res
    aad = res[0]
    aad_len = res[1]
    ciphertext = res[2]
    ciphertext_len = res[3]
    plaintext = ChaCha.chacha(key, nonce, ciphertext, ciphertext_len, 1, 8)
    return [aad, aad_len, plaintext, ciphertext_len]
end function

// Calculates a message authentication code based on the AEAD. Returns a boolean. It's very important to authenticate the AEAD before calling this method.
// @description The aad is a list of 32-bit integers of any length.
// @description The plaintext is a list of 32-bit integers of any length.
// @param {list<number>} key           - a list of 8 32-bit integers
// @param {list<number>} nonce         - a list of 3 32-bit integers
// @param {list<number>} aad           - a list of 32-bit integers, any size
// @returns {number}                   - true or false
ChaCha8Poly1305.verify = function(key, tag, nonce, aead)
    otk = ChaCha8Poly1305.keygen(key, nonce)
    actual_tag = Poly1305.mac(otk, aead, aead.len * 4)
    return actual_tag == tag
end function

// Generates a one-time key for Poly1305 using ChaCha
// RFC 8439 requires 20 rounds for the one-time key.
// @param {list<number>}   key   - a list of 8 32-bit integers
// @param {list<number>}   nonce - a list of 3 32-bit integers
// @returns {list<number>}       - a list of 8 32-bit integers
ChaCha20Poly1305.keygen = function(key, nonce)
    state = ChaCha.assembleState(key, nonce, 0)
    block = [0] * 16
    ChaCha.chachaBlock(block, state, 20)
    return block[:8]
end function

// Assembles the ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) from its constituent parts
// @param {list<number>}   aad            - a list of 32-bit integers, any length
// @param {number}         aad_len        - the length of the aad in bytes
// @param {list<number>}   ciphertext     - a list of 32-bit integers, any length
// @param {number}         ciphertext_len - the length of the ciphertext in bytes
// @returns {list<number>}                - a list of 32-bit integers
ChaCha20Poly1305.AEAD = @ChaCha8Poly1305.AEAD

// Splits the AEAD into its components. Returns [aad , aad_len, ciphertext, ciphertext_len] if the AEAD is well-formed, or an error otherwise.
// @description The AAD and ciphertext can be any length
// @param {list<number>} aead - a list of 32-bit integers
// @returns {list | error}    - if not an error, it returns [aad , aad_len, ciphertext, ciphertext_len] -> [list<number>, number, list<number>, number]
ChaCha20Poly1305.splitAEAD = @ChaCha8Poly1305.splitAEAD

// Encrypts and authenticates the plaintext and aad using the provided key and nonce. Returns [aead, tag]
// @description The AEAD is a list of 32-bit integers of any length depending on the aad and plaintext.
// @description The tag is a list of 4 32-bit integers, and is the Poly1305 message authentication code computed on the AEAD post-encryption.
// @param {list<number>} key           - a list of 8 32-bit integers
// @param {list<number>} nonce         - a list of 3 32-bit integers
// @param {list<number>} aad           - a list of 32-bit integers, any size
// @param {number}       aad_len       - the length of 'aad' in bytes
// @param {list<number>} plaintext     - a list of 32-bit integers, any size
// @param {number}       plaintext_len - the length of 'plaintext' in bytes
// @returns {list}                     - [aead, tag] -> [list<number>, list<number>]
ChaCha20Poly1305.encrypt = function(key, nonce, aad, aad_len, plaintext, plaintext_len)
    otk = ChaCha20Poly1305.keygen(key, nonce)
    ciphertext = ChaCha.chacha(key, nonce, plaintext, plaintext_len, 1, 20)
    aead = ChaCha20Poly1305.AEAD(aad, aad_len, ciphertext, plaintext_len)
    tag = Poly1305.mac(otk, aead, aead.len * 4)
    return [aead, tag]
end function

// Decrypts the AEAD WITHOUT AUTHENTICATING IT using the provided key and nonce. Returns [aad, aad_len, plaintext, plaintext_len]. It's very important to authenticate the AEAD before calling this method.
// @description The aad is a list of 32-bit integers of any length.
// @description The plaintext is a list of 32-bit integers of any length.
// @param {list<number>} key           - a list of 8 32-bit integers
// @param {list<number>} nonce         - a list of 3 32-bit integers
// @param {list<number>} aad           - a list of 32-bit integers, any size
// @returns {list | error}             - [aad, aad_len, plaintext, plaintext_len] -> [list<number>, number, list<number>, number] or an error
ChaCha20Poly1305.decrypt = function(key, nonce, aead)
    res = ChaCha20Poly1305.splitAEAD(aead)
    if typeof(res) == "error" then return res
    aad = res[0]
    aad_len = res[1]
    ciphertext = res[2]
    ciphertext_len = res[3]
    plaintext = ChaCha.chacha(key, nonce, ciphertext, ciphertext_len, 1, 20)
    return [aad, aad_len, plaintext, ciphertext_len]
end function

// Calculates a message authentication code based on the AEAD. Returns a boolean. It's very important to authenticate the AEAD before calling this method.
// @description The aad is a list of 32-bit integers of any length.
// @description The plaintext is a list of 32-bit integers of any length.
// @param {list<number>} key           - a list of 8 32-bit integers
// @param {list<number>} nonce         - a list of 3 32-bit integers
// @param {list<number>} aad           - a list of 32-bit integers, any size
// @returns {number}                   - true or false
ChaCha20Poly1305.verify = function(key, tag, nonce, aead)
    otk = ChaCha20Poly1305.keygen(key, nonce)
    actual_tag = Poly1305.mac(otk, aead, aead.len * 4)
    return actual_tag == tag
end function

end function //-------------

if not minicrypt.hasIndex("ChaCha20Poly1305") then __scope()
globals.remove("__scope")