// ChaCha20 is a symmetric stream cipher that is much faster than the more commonly used AES when hardware acceleration isn't available.
// It's often combined with Poly1305, a keyed hash function that can be used to provide message authentication.
// https://en.wikipedia.org/wiki/ChaCha20-Poly1305
//
// This implementation provides both algorithms separately, as well as combined together. I followed this RFC specification:
// https://www.rfc-editor.org/info/rfc8439/

if not globals.hasIndex("minicrypt") then minicrypt = {}

import_code("./bigint.ms")
import_code("./encode.ms")
import_code("./error.ms")

__scope = function //-------------

minicrypt.Poly1305 = {}
minicrypt.Poly1305.BigInt = new minicrypt.BigInt
minicrypt.Poly1305.BigInt.init(156, 26)

minicrypt.ChaCha = {}

// Edit this if performance is important to your project, but note that this implementation only supports an even number of rounds.
// I recommend 8 rounds, following this paper: https://eprint.iacr.org/2019/1492.pdf
// 7 years have passed, and ChaCha8 is still just as solid: https://www.bfswa.blog/p/6-years-after-too-much-crypto
minicrypt.ChaCha.ROUNDS = 20

minicrypt.ChaCha.POW2 = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888, 1099511627776, 2199023255552, 4398046511104, 8796093022208, 17592186044416, 35184372088832, 70368744177664, 140737488355328, 281474976710656, 562949953421312, 1125899906842624, 2251799813685248, 4503599627370496]

// Performs a xor on a and b, 32 bit integers. Native xor only supports 31 bits...
// @param {number} a
// @param {number} b
// @returns {number}
minicrypt.ChaCha.xor32 = function(a, b)
    a_btm   = a % 2147483648 //2^31
    b_btm   = b % 2147483648
    xor_top = (a - a_btm != b - b_btm) * 2147483648
    return xor_top + bitXor(a_btm, b_btm)
end function

// Calculates 'output = plaintext ^ key'. 'output', 'plaintext' and 'key' should be equally-sized lists of 32-bit integers. For performance reasons, no checks are done to verify the inputs.
// @param {list<number>} output    - output list. Should be initialized as [0] * 16 or recycled
// @param {list<number>} plaintext - list of 0-16 32-bit integers
// @param {list<number>} key       - list of 0-16 32-bit integers
// @returns {null}
minicrypt.ChaCha.xorBlock = function(output, plaintext, key)
    for i in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15][:plaintext.len]
        output[i] = minicrypt.ChaCha.xor32(plaintext[i], key[i])
    end for
end function

// Rotate left (any overflow pops in from the right) a 32-bit value, using faster arithmetic functions
// @param {number}   a - 32-bit value to rotate
// @param {number}   b - rotation amount. Can be any safe integer
// @returns {number}   - rotated value
minicrypt.ChaCha.ROTL = function(a, b)
    c = minicrypt.ChaCha.POW2[32-b]
    return ((a * minicrypt.ChaCha.POW2[b]) + (a / c - a % c / c)) % 4294967296 //2^32
end function

// ChaCha quarter round, an ARX operation. Modifies the ChaCha state directly.
// Four quarter rounds make a full ChaCha round.
// @param {list<number>} x - the ChaCha state, a list of 16 32-bit integers
// @param {number}       i - the first  index
// @param {number}       j - the second index
// @param {number}       k - the third  index
// @param {number}       l - the fourth index
// @returns {null}
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

// Takes a starting ChaCha state and performs 'ChaCha.ROUNDS' (default 20) ChaCha rounds on it, then adds it to the original state again.
// @param {list<number>} output - final state. Should be initialized as [0] * 16 or recycled
// @param {list<number>} input  - initial state, a list of 16 32-bit integers.
// @returns {null}
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

// Creates the correct ChaCha state from the key, nonce, and counter.
// @params {list<number>}  key     - a list of 8 32-bit integers
// @params {list<number>}  nonce   - a list of 3 32-bit integers
// @params {number}        counter - a 32-bit number
// @returns {list<number>}         - the assembled ChaCha state, a list of 16 32-bit integers
minicrypt.ChaCha.assembleState = function(key, nonce, counter)
    return [1634760805, 857760878, 2036477234, 1797285236] +
           key +
           [counter] +
           nonce
end function

// Encrypts or decrypts an encoded message using the ChaCha algorithm.
// @params {list<number>}  key        - a list of 8 32-bit integers. The secret key
// @params {list<number>}  nonce      - a list of 3 32-bit integers. A unique value
// @param {list<number>}   input      - a list of 32-bit integers. The input to be encrypted/decrypted
// @param {number}         byte_count - a 32-bit integer. The length of 'input' in bytes
// @param {number}         [counter]  - a 32-bit integer. The starting ChaCha counter, is used to ensure that (counter + nonce) is unique for each block
// @returns {list<number>}            - a list of 32-bit integers, the same byte count as 'input'
minicrypt.ChaCha.chacha = function(key, nonce, input, byte_count, counter = 1)
    state = minicrypt.ChaCha.assembleState(key, nonce, counter)
    output = []
    key_stream = [0] * 16
    encrypted_block = [0] * 16
    i = -1
    if input.len >= 16 then
        for i in range(0, floor(input.len/16)-1)
            state[12] = counter + i
            minicrypt.ChaCha.chachaBlock(key_stream, state)
            block = input[i*16:i*16+16]
            minicrypt.ChaCha.xorBlock(encrypted_block, block, key_stream)
            output  = output + encrypted_block
        end for
    end if
    if input.len % 16 != 0 then
        i = i + 1
        state[12] = counter + i
        minicrypt.ChaCha.chachaBlock(key_stream, state)
        block = input[i*16:input.len]
        minicrypt.ChaCha.xorBlock(encrypted_block, block, key_stream)
        output = output + encrypted_block[:input.len-i*16]
    end if
    byte_r = byte_count % 4
    if byte_r != 0 then
        output[-1] = output[-1] % minicrypt.ChaCha.POW2[byte_r * 8]
    end if
    return output
end function

// Creates a safe nonce (partially random, partially derived from the plaintext) if the user is unable to provide one with this key property: if plaintext1 -> nonce1 and plaintext2 -> nonce2, then if plaintext1 != plaintext2 then it's extremely unlikely that nonce1 == nonce2
// @params {list<number>}  plaintext - a list of 32-bit integers.
// @returns {list<number>}           - a list of 3 32-bit integers
minicrypt.ChaCha.getHedgedNonce = function(plaintext)
    key = []
    for i in range(8)
        key.push(floor(rnd * 4294967296)) //2^32
    end for
    otn = [hash(plaintext) % 4294967296,
        hash(plaintext + [0]) % 4294967296,
        hash(plaintext + [1]) % 4294967296,
        ]
    if otn[0] < 0 then otn[0] = otn[0] + 4294967296
    if otn[1] < 0 then otn[1] = otn[1] + 4294967296
    if otn[2] < 0 then otn[2] = otn[2] + 4294967296
    zeros = [0, 0, 0]
    nonce = minicrypt.ChaCha.chacha(key, otn, zeros, 12)
    return nonce
end function

// Encrypts a message using a secret key.
// @param {string}           key                    - A hex string, 32 bytes / 64 characters
// @param {string}           plaintext              - Text to encrypt. By default, it supports the entire range of characters, char(0)-char(65535)
// @param {string}           [plaintext_encoding]   - (optional) Format to encode the plaintext with. Supported values are "16bit" (default) and "8bit" (which covers all useful characters and shortens the ciphertext by 50%). 
// @param {string}           [ciphertext_encoding]  - (optional) Format to encode the ciphertext with. Supported values are "base64" (default) and "8bit"
// @param {list<number>}     [nonce]                - (optional) If left as null, it generates a safe, synthetic nonce. If you set this manually, DO NOT EVER reuse the same key/nonce pair for another message
// @param {number}           [counter]              - (optional) Leaving this as 1 is safe. Key generation for Poly1305 requires a value of 0
// @returns {string | error}                        - The encryped message with some metadata for decryption: the byte length is the plaintext byte length + 20 bytes. The default format is base64. If something goes wrong, it returns an error object {"classID": "error"} instead.
//
// @example minicrypt.ChaCha.encrypt("fe46e801a7d3426fe3ee0dbb0eeb7df4173eff4b9fdd9dc7aa817cddc323f77a", "Cha Cha Real Smooth")
minicrypt.ChaCha.encrypt = function(key, plaintext, plaintext_encoding = "16bit", ciphertext_encoding = "base64", nonce = null, counter = 1)
    if typeof(@plaintext_encoding) == "list" then
        encoder = @plaintext_encoding[0]
    else if plaintext_encoding == "16bit" then
        encoder = @minicrypt.Encode.encodeText16
    else if plaintext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha.encrypt", "unsupported_encoding")
    end if

    if typeof(@ciphertext_encoding) == "list" then
        decoder = @ciphertext_encoding[1]
    else if ciphertext_encoding == "base64" then
        decoder = @minicrypt.Encode.toBase64
    else if ciphertext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha.encrypt", "unsupported_encoding")
    end if
    
    if key.len != 64 then return minicrypt.Error("minicrypt.ChaCha.encrypt", "incorrect_key_length")
    key_enc = minicrypt.Encode.hexToB32(key)
    if typeof(key_enc) == "error" then return key_enc

    res = encoder(plaintext)
    if typeof(res) == "error" then return res
    plaintext_enc = res[0]
    plaintext_len = res[1]

    if typeof(nonce) == "string" then nonce = minicrypt.Encode.hexToB32(nonce)
    if nonce == null then nonce = minicrypt.ChaCha.getHedgedNonce(plaintext_enc)

    ciphertext_enc = minicrypt.ChaCha.chacha(key_enc, nonce, plaintext_enc, plaintext_len, counter)
    plaintext_len32 = plaintext_len % 4294967296
    enc = decoder(
        nonce +
        [plaintext_len32, (plaintext_len - plaintext_len32) / 4294967296] + 
        ciphertext_enc, 
        12 + 8 + plaintext_len)
    return enc
end function

// Decrypts a message using a secret key.
// @param {string}           key                    - A hex string, 32 bytes / 64 characters
// @param {string}           ciphertext             - Text to decrypt. The default format is base64
// @param {string}           [plaintext_encoding]   - (optional) Format to encode the plaintext with. Make sure it's the same format used to encode the plaintext
// @param {string}           [ciphertext_encoding]  - (optional) Format to encode the ciphertext with. Make sure it matches the ciphertext
// @param {number}           [counter]              - (optional) Needs to be the same as in the encryption stage
// @returns {string | error}                       - The original message, or an error object {"classID": "error"}
//
// @example minicrypt.ChaCha.decrypt("fe46e801a7d3426fe3ee0dbb0eeb7df4173eff4b9fdd9dc7aa817cddc323f77a", "hxnPfNewn9b3lLo+LAAAAAAAAADK/ZbTfhBgbK4Aftz2V05UF02xIjXl0M3UiPrweYv6FdVJLo6W/7yyojAF/A==")
minicrypt.ChaCha.decrypt = function(key, ciphertext, plaintext_encoding = "16bit", ciphertext_encoding = "base64", counter = 1)
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha.decrypt", "unsupported_encoding")
    end if

    if typeof(@plaintext_encoding) == "list" then
        decoder = @plaintext_encoding[1]
    else if plaintext_encoding == "16bit" then
        decoder = @minicrypt.Encode.decodeText16
    else if plaintext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha.decrypt", "unsupported_encoding")
    end if

    if key.len != 64 then return minicrypt.Error("minicrypt.ChaCha.decrypt", "incorrect_key_length")
    key_enc = minicrypt.Encode.hexToB32(key)
    if typeof(key_enc) == "error" then return key_enc

    res = encoder(ciphertext)
    if typeof(res) == "error" then return res

    msg_enc = res[0]
    msg_len = res[1]
    if msg_enc.len < 5 then return minicrypt.Error("minicrypt.ChaCha.decrypt", "cyphertext_too_short")

    nonce_enc = msg_enc[:3]
    ciphertext_enc = msg_enc[5:]
    ciphertext_len = msg_enc[3] + msg_enc[4] * 4294967296
    if ciphertext_enc.len != ceil(ciphertext_len/4) then return minicrypt.Error("minicrypt.ChaCha.decrypt", "cyphertext_len_mismatch")

    plaintext_enc = minicrypt.ChaCha.chacha(key_enc, nonce_enc, ciphertext_enc, ciphertext_len, counter)
    plaintext_len = ciphertext_len

    plaintext = decoder(plaintext_enc, plaintext_len)
    return plaintext
end function

//------------------------------

// Clamps the "r" value in Poly1305.macRaw by editing it in place. Also returns the clamped value.
// @param {list<number>}   r - a list of 4 32-bit integers
// @returns {list<number>}   - clamped value
minicrypt.Poly1305.clampR = function(r)
    r[0] = r[0] % 268435456
    r[1] = (r[1] - r[1] % 4) % 268435456
    r[2] = (r[2] - r[2] % 4) % 268435456
    r[3] = (r[3] - r[3] % 4) % 268435456
    return r
end function

// Given a secret key and an encoded message of any size, computes a 128 bit fingerprint of that message.
// @param {list<number>}   key        - list of 8 32-bit integers
// @param {list<number>}   msg        - list of 32-bit integers
// @param {number}         byte_count - length of the message in bytes
// @returns {list<number>}            - list of 4 32-bit integers
minicrypt.Poly1305.macRaw = function(key, msg, byte_count)
    r = minicrypt.Poly1305.clampR(key[:4]) + [0]
    r = minicrypt.Encode.B32toB26(r)
    s = minicrypt.Encode.B32toB26(key[4:]) + [0]
    a = minicrypt.Poly1305.BigInt.zero
    p = [67108859, 67108863, 67108863, 67108863, 67108863, 0] //2^130-5
    if msg.len > 0 then
        for i in range(0, msg.len-1, 4)
            n = minicrypt.Encode.B32toB26(msg[i:i+4]) + [0]
            b = 128
            if i + 4 >= msg.len then
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
    end if
    a = minicrypt.Poly1305.BigInt.add(a, s)
    return minicrypt.Encode.B26toB32(a)
end function

// Given a secret key and an encoded message of any size, computes a 128 bit fingerprint of that message.
// @param {string} key                   - A hex string, 32 bytes / 64 characters
// @param {string} ciphertext            - Text to authenticate. The default format is base64
// @param {string} [ciphertext_encoding] - (optional) Format to encode the ciphertext with. Make sure it matches the ciphertext
// @param {string} [mac_encoding]        - (optional) Format to encode the ciphertext with. Make sure it matches the ciphertext
// @returns {string}                     - The message authentication code, encoded with 'mac_encoding' (default = base64)
minicrypt.Poly1305.mac = function(key, ciphertext, ciphertext_encoding = "base64", mac_encoding = "base64")
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return minicrypt.Error("minicrypt.Poly1305.mac", "unsupported_encoding")
    end if

    if typeof(@mac_encoding) == "list" then
        decoder = @mac_encoding[1]
    else if mac_encoding == "base64" then
        decoder = @minicrypt.Encode.toBase64
    else if mac_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return minicrypt.Error("minicrypt.Poly1305.mac", "unsupported_encoding")
    end if

    if key.len != 64 then return minicrypt.Error("minicrypt.Poly1305.mac", "incorrect_key_length")
    key_enc = minicrypt.Encode.hexToB32(key)
    if typeof(key_enc) == "error" then return key_enc
    
    res = encoder(ciphertext)
    if typeof(res) == "error" then return false
    ciphertext_enc = res[0]
    ciphertext_len = res[1]

    mac = minicrypt.Poly1305.macRaw(key_enc, ciphertext_enc, ciphertext_len)
    if typeof(mac) == "error" then return mac

    if typeof(@mac_encoding) == "list" then return decoder(mac)
    return decoder(mac, 16)
end function

// ----------
minicrypt.ChaCha20Poly1305 = {}

// Generates a one-time key for Poly1305 using ChaCha
// @param {list<number>}   key   - a list of 8 32-bit integers
// @param {list<number>}   nonce - a list of 3 32-bit integers
// @returns {list<number>}       - a list of 8 32-bit integers
minicrypt.ChaCha20Poly1305.keygen = function(key, nonce)
    state = minicrypt.ChaCha.assembleState(key, nonce, 0)
    block = [0] * 16
    minicrypt.ChaCha.chachaBlock(block, state)
    return block[:8]
end function

// Assembles the ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) from its constituent parts
// @param {list<number>}   aad            - a list of 32-bit integers, any length
// @param {number}         aad_len        - the length of the aad in bytes
// @param {list<number>}   ciphertext     - a list of 32-bit integers, any length
// @param {number}         ciphertext_len - the length of the ciphertext in bytes
// @returns {list<number>}                - a list of 32-bit integers
minicrypt.ChaCha20Poly1305.AEAD = function(aad, aad_len, ciphertext, ciphertext_len)
    aad_len32 = aad_len % 4294967296
    ciphertext_len32 = ciphertext_len % 4294967296
    return  aad        + [0] * (4 - ceil(aad_len / 4) % 4) +
            ciphertext + [0] * (4 - ceil(ciphertext_len / 4) % 4) + 
            [aad_len32]        + [(aad_len - aad_len32) / 4294967296] +
            [ciphertext_len32] + [(ciphertext_len - ciphertext_len32) / 4294967296]
end function

// Splits the AEAD into its components. Returns [aad , aad_len, ciphertext, ciphertext_len] if the AEAD is well-formed, or an error otherwise.
// @description The AAD and ciphertext can be any length
// @param {list<number>} aead - a list of 32-bit integers
// @returns {list | error}    - if not an error, it returns [aad , aad_len, ciphertext, ciphertext_len] -> [list<number>, number, list<number>, number]
minicrypt.ChaCha20Poly1305.splitAEAD = function(aead)
    if aead.len < 4 then return minicrypt.Error("minicrypt.ChaCha20Poly1305.splitAEAD", "short_aead")
    if aead.len % 4 != 0 then return minicrypt.Error("minicrypt.ChaCha20Poly1305.splitAEAD", "unpadded_aead")
    aad_len = aead[-4] + aead[-3] * 4294967296
    ciphertext_len = aead[-2] + aead[-1] * 4294967296
    aad_padded_len = ceil(aad_len/4) + (4 - ceil(aad_len / 4) % 4)
    ciphertext_padded_len = ceil(ciphertext_len/4) + (4 - ceil(ciphertext_len / 4) % 4)
    if aead.len != aad_padded_len + ciphertext_padded_len + 4 then return minicrypt.Error("minicrypt.ChaCha20Poly1305.splitAEAD", "length_mismatch")
    aad = aead[:ceil(aad_len/4)]
    ciphertext = aead[aad_padded_len : aad_padded_len + ceil(ciphertext_len/4)]
    return [aad, aad_len, ciphertext, ciphertext_len]
end function

// Splits a ChaCha20-Poly1305 into its components. Returns [tag, nonce, aead] if the message is well-formed, or an error otherwise.
// @description The tag is a list of 4 32-bit integers, the nonce is a list of 3 32-bit integers, and the aead is a list of 32-bit integers of any length.
// @param {list<number>} aead - a list of 32-bit integers
// @returns {list | error}    - if not an error, it returns [tag, nonce, aead] -> [list<number>, list<number>, list<number>]
minicrypt.ChaCha20Poly1305.splitMessage = function(msg)
    if msg.len < 11 or msg.len % 4 != 3 then return minicrypt.Error("minicrypt.ChaCha20Poly1305.splitMessage", "malformed_msg")
    return [msg[:4], msg[4:7], msg[7:]]
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
minicrypt.ChaCha20Poly1305.encryptRaw = function(key, nonce, aad, aad_len, plaintext, plaintext_len)
    otk = minicrypt.ChaCha20Poly1305.keygen(key, nonce)
    ciphertext = minicrypt.ChaCha.chacha(key, nonce, plaintext, plaintext_len, 1)
    aead = minicrypt.ChaCha20Poly1305.AEAD(aad, aad_len, ciphertext, plaintext_len)
    tag = minicrypt.Poly1305.macRaw(otk, aead, aead.len * 4)
    return [aead, tag]
end function

// Decrypts the AEAD WITHOUT AUTHENTICATING IT using the provided key and nonce. Returns [aad, aad_len, plaintext, plaintext_len]. It's very important to authenticate the AEAD before calling this method.
// @description The aad is a list of 32-bit integers of any length.
// @description The plaintext is a list of 32-bit integers of any length.
// @param {list<number>} key           - a list of 8 32-bit integers
// @param {list<number>} nonce         - a list of 3 32-bit integers
// @param {list<number>} aad           - a list of 32-bit integers, any size
// @returns {list | error}             - [aad, aad_len, plaintext, plaintext_len] -> [list<number>, number, list<number>, number] or an error
minicrypt.ChaCha20Poly1305.decryptRaw = function(key, nonce, aead)
    res = minicrypt.ChaCha20Poly1305.splitAEAD(aead)
    if typeof(res) == "error" then return res
    aad = res[0]
    aad_len = res[1]
    ciphertext = res[2]
    ciphertext_len = res[3]
    plaintext = minicrypt.ChaCha.chacha(key, nonce, ciphertext, ciphertext_len, 1)
    return [aad, aad_len, plaintext, ciphertext_len]
end function

// Calculates a message authentication code based on the AEAD. Returns [aad, aad_len, plaintext, plaintext_len]. It's very important to authenticate the AEAD before calling this method.
// @description The aad is a list of 32-bit integers of any length.
// @description The plaintext is a list of 32-bit integers of any length.
// @param {list<number>} key           - a list of 8 32-bit integers
// @param {list<number>} nonce         - a list of 3 32-bit integers
// @param {list<number>} aad           - a list of 32-bit integers, any size
// @returns {list}                     - [aad, aad_len, plaintext, plaintext_len] -> [list<number>, number, list<number>, number]
minicrypt.ChaCha20Poly1305.verifyRaw = function(key, tag, nonce, aead)
    otk = minicrypt.ChaCha20Poly1305.keygen(key, nonce)
    actual_tag = minicrypt.Poly1305.macRaw(otk, aead, aead.len * 4)
    return actual_tag == tag
end function

// Creates a partially encrypted, authenticated ciphertext from a message and an AAD (additional authenticated data).
// @description The ciphertext is made of the following parts: the unencrypted AAD, the encrypted message, the nonce, some metadata about the lengths of the various components, and the message authentication code for the AAD + message (not in this order)
// @description You can also create custom encoding and decoding functions and pass them in the 'plaintext_encoding' / 'ciphertext_encoding' args. Instead of a string, pass a list. The first item should be an encoding funcRef, which takes a value and returns a list of 2 items: a list of 32-bit integers (the encoded value) and its length in bytes. The second item should be a decoding funcRef that takes an encoded value (a list of 32-bit numbers) and its length in bytes, and returns its decoded value.
// @param {string}           key                    - A hex string, 32 bytes / 64 characters
// @param {string}           plaintext              - Text to encrypt. By default, it supports the entire range of characters, char(0)-char(65535)
// @param {string}           [aad]                  - (optional) Additional Authenticated Data. It will not be encrypted, but will be authenticated.
// @param {string}           [plaintext_encoding]   - (optional) Format to encode the plaintext with. Supported values are "16bit" (default) and "8bit" (which covers all useful characters and shortens the ciphertext by 50%). 
// @param {string}           [ciphertext_encoding]  - (optional) Format to encode the ciphertext with. Supported values are "base64" (default) and "8bit"
// @param {list<number>}     [nonce]                - (optional) If left as null, it generates a safe, synthetic nonce. If you set this manually, DO NOT EVER reuse the same key/nonce pair for another message
// @returns {string | error}                        - The encryped message with some metadata for decryption: the byte length is the plaintext byte length + 20 bytes. The default format is base64. If something goes wrong, it returns an error object {"classID": "error"} instead.
// @example ChaCha20Poly1305.encrypt("fe46e801a7d3426fe3ee0dbb0eeb7df4173eff4b9fdd9dc7aa817cddc323f77a", "You can look but ya can't touch", "Secrets secrets...")
minicrypt.ChaCha20Poly1305.encrypt = function(key, plaintext, aad = "", plaintext_encoding = "16bit", ciphertext_encoding = "base64", nonce = null)
    if typeof(@plaintext_encoding) == "list" then
        encoder = @plaintext_encoding[0]
    else if plaintext_encoding == "16bit" then
        encoder = @minicrypt.Encode.encodeText16
    else if plaintext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha20Poly1305.encrypt", "unsupported_encoding")
    end if

    if typeof(@ciphertext_encoding) == "list" then
        decoder = @ciphertext_encoding[1]
    else if ciphertext_encoding == "base64" then
        decoder = @minicrypt.Encode.toBase64
    else if ciphertext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha20Poly1305.encrypt", "unsupported_encoding")
    end if

    if key.len != 64 then return minicrypt.Error("minicrypt.ChaCha20Poly1305.encrypt", "incorrect_key_length")
    key_enc = minicrypt.Encode.hexToB32(key)
    if typeof(key_enc) == "error" then return key_enc
    
    enc = encoder(aad)
    if typeof(enc) == "error" then return enc
    aad_enc = enc[0]
    aad_len_bytes = enc[1]
    
    enc = encoder(plaintext)
    if typeof(enc) == "error" then return enc
    plaintext_enc = enc[0]
    plaintext_len_bytes = enc[1]

    if typeof(nonce) == "string" then nonce = minicrypt.Encode.hexToB32(nonce)
    if nonce == null then nonce = minicrypt.ChaCha.getHedgedNonce(aad_enc + plaintext_enc)
    
    enc = minicrypt.ChaCha20Poly1305.encryptRaw(key_enc, nonce, 
                                      aad_enc, aad_len_bytes, 
                                      plaintext_enc, plaintext_len_bytes)
    if typeof(enc) == "error" then return enc
    aead = enc[0]
    tag = enc[1]
    ciphertext = decoder(tag + nonce + aead, 16 + 12 + aead.len * 4)
    return ciphertext
end function

// Authenticates and decrypts a ciphertext. You can choose to skip the verification, but remember to call ChaCha20Poly1305.verify() manually. Returns [aad, plaintext]
// @param {string}           key                    - A hex string, 32 bytes / 64 characters
// @param {string}           ciphertext             - Text to decrypt. By default it expects a base64 string.
// @param {number}           [do_verify]            - (optional) Boolean. If true (default) then verifies the ciphertext before deciphering. If set to false, it's strongly recommended to manually run ChaCha20Poly1305.verify() before calling this method.
// @param {string}           [plaintext_encoding]   - (optional) Format to encode the plaintext with. Supported values are "16bit" (default) and "8bit"
// @param {string}           [ciphertext_encoding]  - (optional) Format to encode the ciphertext with. Supported values are "base64" (default) and "8bit"
// @returns {list | error}                          - [plaintext, aad] -> [string, string] or an error if any verification of decryption step failed
// @example ChaCha20Poly1305.decrypt("fe46e801a7d3426fe3ee0dbb0eeb7df4173eff4b9fdd9dc7aa817cddc323f77a", "CGRP3BOFU+7MPeny/qLfOL2l73AdkjTzBzgpXlkAbwB1ACAAYwBhAG4AIABsAG8AbwBrACAAYgB1AHQAIAB5AGEAIABjAGEAbgAnAHQAIAB0AG8AdQBjAGgAAAAAAAAAAAAAAAAAAAAAAAAAKuxmZRS64jm2RFJIm5oGUi9SHu2nzMu1NoHZZtv5KYU0QrUdAAAAAAAAAAAAAAAAPgAAAAAAAAAkAAAAAAAAAA==")
// @example > ["Secrets secrets...", "You can look but ya can't touch"]
minicrypt.ChaCha20Poly1305.decrypt = function(key, ciphertext, do_verify = true, plaintext_encoding = "16bit", ciphertext_encoding = "base64")
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha20Poly1305.decrypt", "unsupported_encoding")
    end if

    if typeof(@plaintext_encoding) == "list" then
        decoder = @plaintext_encoding[1]
    else if plaintext_encoding == "16bit" then
        decoder = @minicrypt.Encode.decodeText16
    else if plaintext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha20Poly1305.decrypt", "unsupported_encoding")
    end if

    if key.len != 64 then return minicrypt.Error("minicrypt.ChaCha20Poly1305.decrypt", "incorrect_key_length")
    key_enc = minicrypt.Encode.hexToB32(key)
    if typeof(key_enc) == "error" then return key_enc

    res = encoder(ciphertext)
    if typeof(res) == "error" then return res
    ciphertext_enc = res[0]

    res = minicrypt.ChaCha20Poly1305.splitMessage(ciphertext_enc)
    if typeof(res) == "error" then return res

    tag_enc = res[0]
    nonce_enc = res[1]
    aead_enc = res[2]

    if do_verify then
        verify = minicrypt.ChaCha20Poly1305.verifyRaw(key_enc, tag_enc, nonce_enc, aead_enc)
        if not verify then return minicrypt.Error("minicrypt.ChaCha20Poly1305.decrypt", "verification_failed")
    end if

    enc = minicrypt.ChaCha20Poly1305.decryptRaw(key_enc, nonce_enc, aead_enc)
    if typeof(enc) == "error" then return enc

    aad_enc = enc[0]
    aad_len_bytes = enc[1]
    plaintext_enc = enc[2]
    plaintext_len_bytes = enc[3]
    aad = decoder(aad_enc, aad_len_bytes)
    plaintext = decoder(plaintext_enc, plaintext_len_bytes)
    if typeof(aad) == "error" then return aad
    if typeof(plaintext) == "error" then return plaintext

    return [plaintext, aad]
end function

// Verifies a ciphertext. This method tests the authenticity and integrity of the message.
// @param {string}           key                    - A hex string, 32 bytes / 64 characters
// @param {string}           ciphertext             - Text to decrypt. By default it expects a base64 string.
// @param {string}           [plaintext_encoding]   - (optional) Format to encode the plaintext with. Supported values are "16bit" (default) and "8bit"
// @param {string}           [ciphertext_encoding]  - (optional) Format to encode the ciphertext with. Supported values are "base64" (default) and "8bit"
// @returns {number | error}                        - boolean, or error if ciphertext_encoding is not supported
// @example ChaCha20Poly1305.verify("fe46e801a7d3426fe3ee0dbb0eeb7df4173eff4b9fdd9dc7aa817cddc323f77a", "CGRP3BOFU+7MPeny/qLfOL2l73AdkjTzBzgpXlkAbwB1ACAAYwBhAG4AIABsAG8AbwBrACAAYgB1AHQAIAB5AGEAIABjAGEAbgAnAHQAIAB0AG8AdQBjAGgAAAAAAAAAAAAAAAAAAAAAAAAAKuxmZRS64jm2RFJIm5oGUi9SHu2nzMu1NoHZZtv5KYU0QrUdAAAAAAAAAAAAAAAAPgAAAAAAAAAkAAAAAAAAAA==")
// @example > true
minicrypt.ChaCha20Poly1305.verify = function(key, ciphertext, ciphertext_encoding = "base64")
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha20Poly1305.verify", "unsupported_encoding")
    end if

    if key.len != 64 then return minicrypt.Error("minicrypt.ChaCha20Poly1305.verify", "incorrect_key_length")
    key_enc = minicrypt.Encode.hexToB32(key)
    if typeof(key_enc) == "error" then return key_enc
    
    res = encoder(ciphertext)
    if typeof(res) == "error" then return false
    ciphertext_enc = res[0]

    res = minicrypt.ChaCha20Poly1305.splitMessage(ciphertext_enc)
    if typeof(res) == "error" then return false

    tag_enc = res[0]
    nonce_enc = res[1]
    aead_enc = res[2]

    verify = minicrypt.ChaCha20Poly1305.verifyRaw(key_enc, tag_enc, nonce_enc, aead_enc)
    if typeof(verify) == "error" then return false
    return verify
end function

// Obtain the Additional Authenticated Data from a ciphertext. This does not require a key.
// @param {string}           ciphertext             - Text to decrypt. By default it expects a base64 string.
// @param {string}           [plaintext_encoding]   - (optional) Format to encode the plaintext with. Supported values are "16bit" (default) and "8bit"
// @param {string}           [ciphertext_encoding]  - (optional) Format to encode the ciphertext with. Supported values are "base64" (default) and "8bit"
// @returns {string | error}                        - The AAD in plaintext, or an error if the ciphertext is not well-formed
// @example ChaCha20Poly1305.getAad("CGRP3BOFU+7MPeny/qLfOL2l73AdkjTzBzgpXlkAbwB1ACAAYwBhAG4AIABsAG8AbwBrACAAYgB1AHQAIAB5AGEAIABjAGEAbgAnAHQAIAB0AG8AdQBjAGgAAAAAAAAAAAAAAAAAAAAAAAAAKuxmZRS64jm2RFJIm5oGUi9SHu2nzMu1NoHZZtv5KYU0QrUdAAAAAAAAAAAAAAAAPgAAAAAAAAAkAAAAAAAAAA==")
// @example > "You can look but ya can't touch"
minicrypt.ChaCha20Poly1305.getAad = function(ciphertext, plaintext_encoding = "16bit", ciphertext_encoding = "base64")
    if typeof(@ciphertext_encoding) == "list" then
        encoder = @ciphertext_encoding[0]
    else if ciphertext_encoding == "base64" then
        encoder = @minicrypt.Encode.fromBase64
    else if ciphertext_encoding == "8bit" then
        encoder = @minicrypt.Encode.encodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha20Poly1305.getAad", "unsupported_encoding")
    end if

    if typeof(@plaintext_encoding) == "list" then
        decoder = @plaintext_encoding[1]
    else if plaintext_encoding == "16bit" then
        decoder = @minicrypt.Encode.decodeText16
    else if plaintext_encoding == "8bit" then
        decoder = @minicrypt.Encode.decodeText8
    else
        return minicrypt.Error("minicrypt.ChaCha20Poly1305.getAad", "unsupported_encoding")
    end if

    res = encoder(ciphertext)
    if typeof(res) == "error" then return res
    ciphertext_enc = res[0]

    res = minicrypt.ChaCha20Poly1305.splitMessage(ciphertext_enc)
    if typeof(res) == "error" then return res
    aead_enc = res[2]

    res = minicrypt.ChaCha20Poly1305.splitAEAD(aead_enc)
    if typeof(res) == "error" then return res

    aad_enc = res[0]
    aad_len = res[1]
    aad = decoder(aad_enc, aad_len)
    return aad
end function

end function //-------------

if not minicrypt.hasIndex("ChaCha20Poly1305") then __scope()
globals.remove("__scope")