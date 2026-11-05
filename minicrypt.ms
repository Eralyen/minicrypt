import_code("src/chacha20-poly1305")
import_code("src/blake3.ms")
import_code("src/x25519.ms")
import_code("src/bigint.ms")
import_code("src/encode.ms")
import_code("src/random.ms")
import_code("src/utils.ms")

// ==== KEY GENERATION ====

__scope = function // START OF SCOPE

locals.minicrypt = minicrypt
locals.X25519 = minicrypt.X25519
locals.BLAKE3 = minicrypt.BLAKE3
Random = minicrypt.Random
Error = @minicrypt.Error

minicrypt.BOX_KEYLEN = 32
minicrypt.SECRETBOX_KEYLEN = 32
minicrypt.AUTH_KEYLEN = 32

minicrypt.box_keypair = function
    KEYLEN = minicrypt.BOX_KEYLEN
    sk = minicrypt.rand_stream(KEYLEN)[1]
    pk = [0] * KEYLEN
    // 1073741824 = 2^30. Discards top 2 bits and set the second highest bit
    sk[-1] = sk[-1] % 1073741824 + 1073741824
    // Discards bottom 3 bits
    sk[0] = sk[0] - sk[0] % 8
    sk_16 = []
    pk_16 = [0] * KEYLEN * 2
    for w in sk
        low = w % 65536
        sk_16 = sk_16 + [low, (w-low) / 65536]
    end for
    X25519.scalarMult(pk_16, sk_16, X25519.G)
    for i in range(0, KEYLEN-1)
        pk[i] = pk_16[i*2] + pk_16[i*2+1] * 65536
    end for
    return [[KEYLEN, pk], [KEYLEN, sk]]
end function

minicrypt.sign_keypair = function
    exit("<color=red>NOT IMPLEMENTED")
end function

minicrypt.secretbox_key = function
    return minicrypt.rand_stream(minicrypt.SECRETBOX_KEYLEN)
end function

// TODO: BLAKE3 key derivation function

// TODO: X25519 key blinding

// TODO: Ed25519 key blinding

// BLAKE3 key derivation
minicrypt.secretbox_subkey = function(key, context)
    KEYLEN = minicrypt.SECRETBOX_KEYLEN
    hs = BLAKE3.startDeriveKey(context[1], context[0])
    BLAKE3.updateHash(hs, key[1], key[0])
    subkey = BLAKE3.finalizeHash(hs)
    return [KEYLEN, subkey]
end function


// ==== PUBLIC KEY ENCRYPTION ====

// Curve25519ChaCha8Poly1305
minicrypt.box = function(message, nonce, pubkey, privkey)
end function
minicrypt.box_open = function(box, nonce, pubkey, privkey)
end function
minicrypt.box_labeled = function(message, label, nonce, pubkey, privkey)
end function
minicrypt.box_labeled_read = function(box)
end function
minicrypt.box_labeled_open = function(box, nonce, pubkey, privkey)
end function


// ==== SYMMETRIC ENCRYPTION ====

// ChaCha8-Poly1305 (Authenticated Encryption)
minicrypt.secretbox = function(message, nonce, key)
end function
minicrypt.secretbox_open = function(secretbox, nonce, key)
end function

// ChaCha8-Poly1305 (AEAD)
minicrypt.secretbox_labeled = function(message, label, nonce, key)
end function
minicrypt.secretbox_labeled_read = function(secretbox)
end function
minicrypt.secretbox_labeled_open = function(secretbox, nonce, key)
end function

// ChaCha8 keystream
minicrypt.stream = function(bytes, nonce, key)
end function
// ChaCha8 encryption/decryption
minicrypt.stream_xor = function(message, nonce, key)
end function

// BLAKE3 authentication (keyed hash)
minicrypt.auth = function(message, key)
    hs = BLAKE3.startKeyedHash(key)
    BLAKE3.updateHash(hs, message[1], message[0])
    return [minicrypt.AUTH_KEYLEN, BLAKE3.finalizeHash(hs)]
end function

minicrypt.auth_verify = function(auth, message, key)
    hs = BLAKE3.startKeyedHash(key)
    BLAKE3.updateHash(hs, message[1], message[0])
    return [minicrypt.AUTH_KEYLEN, BLAKE3.finalizeHash(hs)] == auth
end function

// Poly1305 one-time authentication
minicrypt.onetimeauth = function(message, key)
end function
minicrypt.onetimeauth_verify = function(auth, message, key)
end function

// ==== HASHING AND CSPRNG ====

// BLAKE3 hash
minicrypt.hash = function(message, out_len = 32)
    if out_len < 1 then return [0, []]
    p = [4294967296, 256, 65536, 16777216]
    r = out_len % 4
    w = (out_len - r) / 4
    hs = BLAKE3.startHash
    BLAKE3.updateHash(hs, message[1], message[0])
    hash = BLAKE3.finalizeHash(hs, w + (r > 0))
    hash[-1] = hash[-1] % p[r]
    return [out_len, hash]
end function

// Returns a random floating point number in [0, 1)
// @returns {number}
minicrypt.random = function
    w = Random.getRandomWords(2)
    return ((w[1] % 2097152) + (w[0] / 4294967296)) / 2097152
end function

// Returns a random integer in [0, 4294967296)
// @returns {number}
minicrypt.rand_int32 = function
    return Random.getRandomWords(1)[0]
end function

// Returns a random integer in [0, 9007199254740992)
// @returns {number}
minicrypt.rand_int53 = function
    w = Random.getRandomWords(2)
    return (w[1] % 2097152) * 4294967296 + w[0]
end function

// Returns a random integer in [a, b)
// @param {number} a
// @param {number} b
// @returns {number}
minicrypt.randrange = function(a, b)
    // Constant time swap: if a > b then swap a and b
    t = (a > b) * (a - b)
    a = a - t
    b = b + t 
    return minicrypt.rand_int53 % (b - a) + a
end function

// Returns 'out_len' random bytes as a list of 32-bit integers.
// @param {number} out_len
// @returns {list<number>}
minicrypt.rand_stream = function(out_len)
    if out_len < 1 then return [0, []]
    p = [4294967296, 256, 65536, 16777216]
    r = out_len % 4
    w = (out_len - r) / 4
    // Get ceil(out_len/4) random words
    w = Random.getRandomWords(w + (r > 0))
    // Trim the last word if out_len is not a multiple of 4
    w[-1] = w[-1] % p[r]
    return [out_len, w]
end function

// Halts execution for the specified amount of time (default 1 second). Uses this time to harvest entropy and pregenerate a random stream. Configurable through minicrypt.Random.MAX_PREGEN_ENTROPY and minicrypt.Random.MAX_PREGEN_STREAM
// Not as precise as the wait intrinsic.
// @param {number} [seconds] - (optional) How long to wait in seconds. Can be a floating point number
// @returns {null}
minicrypt.wait = function(seconds = 1)
    t = time
    if Random.samples_entropy < Random.MAX_PREGEN_ENTROPY then
        Random.harvestEntropy(Random.MAX_PREGEN_ENTROPY, seconds)
    end if
    if time - t < seconds and Random.output.len < Random.MAX_PREGEN_STREAM then
        while time - t < seconds and Random.output.len < Random.MAX_PREGEN_STREAM
            Random.pregenWords
        end while
    end if
    t2 = time
    if t2 - t < seconds then wait(seconds - (t2-t))
end function

end function // END OF SCOPE
__scope()
globals.remove("__scope")


// ==== EXAMPLE USAGE ====
// key = minicrypt.fromHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")
// plain = minicrypt.from8bitString("Plaintext")
// msg = minicrypt.from16bitString("arbitrary string")
// sbox = minicrypt.secretbox_labeled(msg, plain, 0, key)
// minicrypt.attach_nonce(sbox, 0)
// nonce = minicrypt.detach_nonce(sbox)
// msg2 = minicrypt.secretbox_labeled_open(sbox, nonce, key)