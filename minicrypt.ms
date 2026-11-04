import_code("src/chacha20-poly1305")
import_code("src/blake3.ms")
import_code("src/x25519.ms")
import_code("src/bigint.ms")
import_code("src/encode.ms")
import_code("src/random.ms")
import_code("src/utils.ms")

// ==== KEY GENERATION ====

// Random module
minicrypt.box_keypair = function
end function
minicrypt.sign_keypair = function
end function
minicrypt.secretbox_key = function
end function

// BLAKE3 key derivation function
minicrypt.box_subkeys = function(privkey, context)
end function

// X25519 key blinding
minicrypt.box_keypair_blind = function(privkey, blind)
end function

// Ed25519 key blinding
minicrypt.sign_keypair_blind = function(privkey, blind)
end function

// BLAKE3 key derivation
minicrypt.secretbox_subkey = function(key, context)
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
end function
minicrypt.auth_verify = function(auth, message, key)
end function

// Poly1305 one-time authentication
minicrypt.onetimeauth = function(message, key)
end function
minicrypt.onetimeauth_verify = function(auth, message, key)
end function

// ==== HASHING AND CSPRNG ====

// BLAKE3 hash
minicrypt.hash = function(message)
end function

// Random module
minicrypt.rand_double = function
end function
minicrypt.rand_int32 = function
end function
minicrypt.rand_int53 = function
end function
minicrypt.randrange = function(a, b)
end function
minicrypt.rand_stream = function(bytes)
end function


// ==== EXAMPLE USAGE ====
// key = minicrypt.fromHex("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c")
// plain = minicrypt.from8bitString("Plaintext")
// msg = minicrypt.from16bitString("arbitrary string")
// sbox = minicrypt.secretbox_labeled(msg, plain, 0, key)
// minicrypt.attach_nonce(sbox, 0)
// nonce = minicrypt.detach_nonce(sbox)
// msg2 = minicrypt.secretbox_labeled_open(sbox, nonce, key)