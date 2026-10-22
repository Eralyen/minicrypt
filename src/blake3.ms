// Blake3 is a fast, multipurpose cryptographic hash function
// https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3
// https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
// https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
// The max size for cv_stack is 2^24, so this algorithm can compute the hash of an input 2^(2^24) words long.

if not globals.hasIndex("minicrypt") then minicrypt = {}
import_code("./encode.ms")
import_code("./math.ms")
import_code("./error.ms")

__scope = function //-------------

minicrypt.BLAKE3 = {}

minicrypt.BLAKE3.IV = [
    1779033703,
    3144134277,
    1013904242,
    2773480762,
    1359893119,
    2600822924,
    528734635,
    1541459225,
]

CHUNK_START         = 1
CHUNK_END           = 2
PARENT              = 4
ROOT                = 8
KEYED_HASH          = 16
DERIVE_KEY_CONTEXT  = 32
DERIVE_KEY_MATERIAL = 64

POW256 = [1, 256, 65536, 16777216, 4294967296]

// The BLAKE3 quarter-round function. It mixes two input words x and y into four words indexed by a, b, c, and d in the working array v[0..15], which gets modified in place.
// @param {list<number>} v - a list if 16 32-bit integers
// @param {number} a - an index 0-15
// @param {number} b - an index 0-15
// @param {number} c - an index 0-15
// @param {number} d - an index 0-15
// @param {number} x - a 32-bit integer
// @param {number} y - a 32-bit integer
// @returns {null}
minicrypt.BLAKE3.G = function(v, a, b, c, d, x, y)
    v[a] = (v[a] + v[b] + x) % 4294967296
    v[d] = rotr(xor32(v[d], v[a]), 16)
    v[c] = (v[c] + v[d])     % 4294967296
    v[b] = rotr(xor32(v[b], v[c]), 12)
    v[a] = (v[a] + v[b] + y) % 4294967296
    v[d] = rotr(xor32(v[d], v[a]), 8)
    v[c] = (v[c] + v[d])     % 4294967296
    v[b] = rotr(xor32(v[b], v[c]), 7)
end function

G = @minicrypt.BLAKE3.G
xor32 = @minicrypt.Math.xor32
rotr = @minicrypt.Math.rotr

// BLAKE3's compression function. Returns the untruncated state.
// @param {list<number>} h     - the input chaining value, a list of 8 32-bit integers
// @param {list<number>} m     - the message, a list of 16 32-bit integers
// @param {list<number>} t     - the counter, a list of 2 32-bit integers
// @param {number}       b     - the number of input bytes, 32-bit
// @param {number} d           - a set of domain separation bit flags
// @returns {list<number>}     - a list of 16 32-bit integers
minicrypt.BLAKE3.compress = function(h, m, t, b, d)
    v = h[:] + minicrypt.BLAKE3.IV[:4] + t + [b, d]
    for i in [0,1,2,3,4,5]
        G(v, 0, 4,  8, 12, m[ 0], m[ 1])
        G(v, 1, 5,  9, 13, m[ 2], m[ 3])
        G(v, 2, 6, 10, 14, m[ 4], m[ 5])
        G(v, 3, 7, 11, 15, m[ 6], m[ 7])
        
        G(v, 0, 5, 10, 15, m[ 8], m[ 9])
        G(v, 1, 6, 11, 12, m[10], m[11])
        G(v, 2, 7,  8, 13, m[12], m[13])
        G(v, 3, 4,  9, 14, m[14], m[15])

        m = [m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13], m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8]]
    end for
    G(v, 0, 4,  8, 12, m[ 0], m[ 1])
    G(v, 1, 5,  9, 13, m[ 2], m[ 3])
    G(v, 2, 6, 10, 14, m[ 4], m[ 5])
    G(v, 3, 7, 11, 15, m[ 6], m[ 7])
    
    G(v, 0, 5, 10, 15, m[ 8], m[ 9])
    G(v, 1, 6, 11, 12, m[10], m[11])
    G(v, 2, 7,  8, 13, m[12], m[13])
    G(v, 3, 4,  9, 14, m[14], m[15])

    for i in [0,1,2,3,4,5,6,7]
        v[i] = xor32(v[i], v[i+8])
        v[i+8] = xor32(v[i+8], h[i])
    end for
    return v
end function

// Returns a 64 byte (or out_len * 4 bytes) hash
// @param{list} output      - the chaining state before compression
// @param{number} [out_len] - (optional) the amount of words to return. 
// @returns {list<number>}  - The hash, a list of 32-bit integers
minicrypt.BLAKE3.rootOutputBytes = function(output, out_len = 16)
    if out_len == 0 then return []
    output_block_counter = [0, 0]
    out_block = []
    flags = output[4] + ROOT
    for i in range(0, out_len-1, 16)
        words = minicrypt.BLAKE3.compress(output[0], output[1], output_block_counter, output[3], flags)
        out_block = out_block + words
        output_block_counter[1] = output_block_counter[1] + ((output_block_counter[0]+1) - ((output_block_counter[0]+1) % 4294967296)) / 4294967296
        output_block_counter[0] = (output_block_counter[0]+1) % 4294967296
    end for
    return out_block[:out_len]
end function

// Takes 2 child nodes and creates the state right before compression: 
// @description output[0] = input chaining value
// @description output[1] = block
// @description output[2] = block counter
// @description output[3] = block length
// @description output[4] = flags
// @param {list<number>} left_child_cv  - a list of 8 32-bit integers
// @param {list<number>} right_child_cv - a list of 8 32-bit integers
// @param {list<number>} key            - the key or IV. A list of 32-bit integers
// @param {number} flags                - a set of domain separation bit flags
// @returns {list}                      - the chaining state before compression
minicrypt.BLAKE3.parentOutput = function(left_child_cv, right_child_cv, key, flags)
    flags = flags + PARENT
    return [key, left_child_cv + right_child_cv, [0, 0], 64, flags]
end function

// Takes 2 child nodes and compresses them.
// @param {list<number>} left_child_cv  - a list of 8 32-bit integers
// @param {list<number>} right_child_cv - a list of 8 32-bit integers
// @param {list<number>} key            - the key or IV. A list of 32-bit integers
// @param {number} flags                - a set of domain separation bit flags
// @returns {list<number>}              - the chaining value of the parent
minicrypt.BLAKE3.parentCV = function(left_child_cv, right_child_cv, key, flags)
    output = minicrypt.BLAKE3.parentOutput(left_child_cv, right_child_cv, key, flags)
    return minicrypt.BLAKE3.compress(output[0], output[1], output[2], output[3], output[4])[:8]
end function

// Returns the state for a new chunk: [chaining_value, chunk_counter, block, blocks_compressed, flags, pad_bytes]
// @param {list<number>} key      - the key or IV. A list of 32-bit integers
// @param {number}       counter  - the chunk counter
// @param {number}       flags    - a set of domain separation bit flags
// @returns {list}>
minicrypt.BLAKE3.newChunkState = function(key, counter, flags)
    return [key, counter, [], 0, flags, 0]
end function

// Add more input to be hashed, which updates the chunk state. This can be called several times.
// @description chunk_state[0] = chaining_value
// @description chunk_state[1] = chunk_counter
// @description chunk_state[2] = block
// @description chunk_state[3] = blocks_compressed
// @description chunk_state[4] = flags
// @description chunk_state[5] = pad_bytes, 0-3
// @param {list}         chunk_state - a list of the chunk state, see above
// @param {list<number>} input       - part of the input, a list of 32-bit integers
// @returns {null}
minicrypt.BLAKE3.updateBlock = function(chunk_state, input)
    while input.len > 0
        // If the block buffer is full, compress it and clear it. More
        // input is coming, so this compression is not CHUNK_END.
        if chunk_state[2].len == 16 then 
            flags = chunk_state[4] // chunk_state[4] = flags
            flags = flags + CHUNK_START * (chunk_state[3] == 0) // chunk_state[3] = blocks_compressed
            chunk_state[0] = minicrypt.BLAKE3.compress(chunk_state[0], chunk_state[2], chunk_state[1], chunk_state[2].len * 4, flags)[:8] // chunk_state[0] = chaining_value
            chunk_state[3] = chunk_state[3] + 1 // chunk_state[3] = blocks_compressed
            chunk_state[2] = [] //chunk_state[2] = block
        end if
        want = 16 - chunk_state[2].len //chunk_state[2] = block
        new_slice = input[:want]
        chunk_state[2] = chunk_state[2] + new_slice //chunk_state[2] = block
        input = input[want:]
    end while
end function

// Turns the last chunk state into a block output state
// @param {list}   chunk_state - a list of the chunk state
// @returns {list}             - a list of the output, the block state
minicrypt.BLAKE3.outputChunks = function(chunk_state)
    flags = chunk_state[4]
    flags = flags + CHUNK_START * (chunk_state[3] == 0)
    flags = flags + CHUNK_END
    return [chunk_state[0], chunk_state[2] + [0] * (16 - chunk_state[2].len), chunk_state[1], chunk_state[2].len * 4 - chunk_state[5], flags]
end function

// Returns the beginning state for an unkeyed hash. Follow it up with minicrypt.BLAKE3.updateHash() and then minicrypt.BLAKE3.finalizeHash()
// @description hash_state[0] = chunk state
// @description hash_state[1] = key
// @description hash_state[2] = CV stack
// @description hash_state[3] = flags
// @returns {list}
minicrypt.BLAKE3.startHash = function
    chunk_state = minicrypt.BLAKE3.newChunkState(minicrypt.BLAKE3.IV, [0, 0], 0)
    hash_state = [chunk_state, minicrypt.BLAKE3.IV, [], 0]
    return hash_state
end function

// Returns the beginning state for a keyed hash. Follow it up with minicrypt.BLAKE3.updateHash() and then minicrypt.BLAKE3.finalizeHash()
// @description hash_state[0] = chunk state
// @description hash_state[1] = key
// @description hash_state[2] = CV stack
// @description hash_state[3] = flags
// @param {list<number>} key - the 256-bit key. A list of 8 32-bit integers
// @returns {list}
minicrypt.BLAKE3.startKeyedHash = function(key)
    flags = KEYED_HASH
    chunk_state = minicrypt.BLAKE3.newChunkState(key, [0, 0], flags)
    hash_state = [chunk_state, key, [], flags]
    return hash_state
end function
// Returns the beginning state for key derivation. Follow it up with minicrypt.BLAKE3.updateHash() and then minicrypt.BLAKE3.finalizeHash()
// @description hash_state[0] = chunk state
// @description hash_state[1] = key
// @description hash_state[2] = CV stack
// @description hash_state[3] = flags
// @param {list<number>} context  - the key context. A list of 32-bit integers
// @param {list<number>} byte_len - the length of the context in bytes
// @returns {list}
minicrypt.BLAKE3.startDeriveKey = function(context, byte_len)
    key = minicrypt.BLAKE3.IV
    chunk_state = minicrypt.BLAKE3.newChunkState(key, [0, 0], DERIVE_KEY_CONTEXT)
    hash_state = [chunk_state, key, [], DERIVE_KEY_CONTEXT]
    minicrypt.BLAKE3.updateHash(hash_state, context, byte_len)
    context_key = minicrypt.BLAKE3.finalizeHash(hash_state, 8)
    chunk_state = minicrypt.BLAKE3.newChunkState(context_key, [0, 0], DERIVE_KEY_MATERIAL)
    hash_state = [chunk_state, context_key, [], DERIVE_KEY_MATERIAL]
    return hash_state
end function

// Adds a CV to the chunk. See the BLAKE3 paper, section 5.1.2
// @param {list<list<number>>} cv_stack     - the chaining value stack. a list of chaining values, which are lists of 8 32-bit integers
// @param {list<number>}       new_cv       - the new chaining value, a list of 8 32-bit integers
// @param {number}             total_chunks - the total amount of chunks added, including the new_cv
// @param {list<number>}       key          - the key or IV. A list of 32-bit integers
// @param {list<number>}       flags        - a set of domain separation bit flags
// @returns {null}
minicrypt.BLAKE3.addChunkChainingValue = function(cv_stack, new_cv, total_chunks, key, flags)
    while total_chunks % 2 == 0
        new_cv = minicrypt.BLAKE3.parentCV(cv_stack.pop, new_cv, key, flags)
        total_chunks = total_chunks / 2
    end while
    cv_stack.push(new_cv)
end function

// Hashes the input. Can be called multiple times to keep adding input data. Updates the hash_state in place, follow it up with minicrypt.BLAKE3.finalizeHash()
// @param {list}         hash_state - the hash state, a list of 4 32-bit integers
// @param {list<number>} input      - the input, a list of 32-bit integers
// @param {number}       byte_len   - the length of the input in bytes
// @returns {null}
minicrypt.BLAKE3.updateHash = function(hash_state, input, byte_len)
    if byte_len == 0 then return
    r = byte_len % 4       // valid bytes in the last input word (0 = all complete)
    n = (byte_len - r) / 4 // number of complete words
    complete = input
    tail = 0
    if r > 0 then
        tail = complete[n] % POW256[r]
        complete = input[:n]
    end if
    pad = hash_state[0][5]
    if pad > 0 then
        k = 4 - pad
        p = hash_state[0][2].pop
        hash_state[0][5] = 0
        mul = POW256[k]
        div = POW256[4-k]
        shifted = []
        for w in complete
            part = w % div
            shifted.push(p + part*mul)
            p = (w - part) / div
        end for
        complete = shifted
        if r > 0 then
            if k + r < 4 then
                p = p + tail*mul
                k = k + r
            else
                part = tail % div
                complete.push(p + part*mul)
                p = (tail - part) / div
                k = k + r - 4
            end if
        end if
        if k > 0 then complete.push(p)
        pad = (4 - k) % 4
    else if r > 0 then
        complete.push(tail)
        pad = 4 - r
    end if

    while complete.len != 0
        if (64 * hash_state[0][3]) + (4 * hash_state[0][2].len) == 1024 then
            chunk_output = minicrypt.BLAKE3.outputChunks(hash_state[0])
            chunk_cv = minicrypt.BLAKE3.compress(chunk_output[0], chunk_output[1], chunk_output[2], chunk_output[3], chunk_output[4])[:8]
            counter = hash_state[0][1] // [low, high]
            total_chunks = counter[0] + counter[1] * 4294967296 + 1
            minicrypt.BLAKE3.addChunkChainingValue(hash_state[2], chunk_cv, total_chunks, hash_state[1], hash_state[3])
            low = total_chunks % 4294967296
            high = (total_chunks - low) / 4294967296
            hash_state[0] = minicrypt.BLAKE3.newChunkState(hash_state[1], [low, high], hash_state[3])
        end if
        want = 256 - (16 * hash_state[0][3]) - hash_state[0][2].len
        new_slice = complete[:want]
        minicrypt.BLAKE3.updateBlock(hash_state[0], new_slice)
        complete = complete[want:]
    end while
    hash_state[0][5] = pad
end function

// Finalizes the hash and returns the result, by default a 256-bit number (as a list of 8 32-bit integers)
// @param {list}   hash_state - the hash state, a list of 4 32-bit integers
// @param {number} [out_len]  - (optional) the desired length of the output in words. If you need to a byte length that's not a multiple of 4, truncate it.
// @returns{list<number>}     - the output hash, a list of out_len 32-bit 
minicrypt.BLAKE3.finalizeHash = function(hash_state, out_len = 8)
    // Starting with the Output from the current chunk, compute all the
    // parent chaining values along the right edge of the tree, until we
    // have the root Output.
    output = minicrypt.BLAKE3.outputChunks(hash_state[0])
    parent_nodes_remaining = hash_state[2].len
    while parent_nodes_remaining > 0
        parent_nodes_remaining = parent_nodes_remaining - 1
        output = minicrypt.BLAKE3.parentOutput(
            hash_state[2][parent_nodes_remaining],
            minicrypt.BLAKE3.compress(output[0], output[1], output[2], output[3], output[4])[:8],
            hash_state[1],
            hash_state[3]) // flag
    end while
    output_hash = minicrypt.BLAKE3.rootOutputBytes(output, out_len)
    return output_hash
end function

// Hashes an input string, returning a 32-byte hex string.
// @param {string} input            - text to hash. By default, it supports the entire range of characters, char(0)-char(65535)
// @param {number} [out_byte_len]   - (optional) byte length of the output hash
// @param {string} [input_encoding] - (optional) format to encode the input string with
// @param {string} [hash_encoding]  - (optional) format to encode the output hash with
// @returns {string}                - the hash
// @example minicrypt.BLAKE3.hash("Hello BLAKE3!")
minicrypt.BLAKE3.hash = function(input, out_byte_len = 32, input_encoding = "16bit", hash_encoding = "hex")
    ie = minicrypt.Encode.getEncoding(input_encoding)
    if ie == null then return minicrypt.Error("minicrypt.BLAKE3.hash", "unsupported_encoding")
    encode = ie[0]

    he = minicrypt.Encode.getEncoding(hash_encoding)
    if he == null then return minicrypt.Error("minicrypt.BLAKE3.hash", "unsupported_encoding")
    decode = he[1]

    res = encode(input)
    if typeof(res) == "error" then return res
    input_raw = res[0]
    input_len = res[1]

    hash_state = minicrypt.BLAKE3.startHash
    minicrypt.BLAKE3.updateHash(hash_state, input_raw, input_len)
    hash_raw = minicrypt.BLAKE3.finalizeHash(hash_state, ceil(out_byte_len/4))

    hash = decode(hash_raw, out_byte_len)
    return hash
end function

// Hashes an input string using a secret key, returning a 32-byte hex string.
// @param {string} key              - the secret key. By default a hex string, 32 bytes / 64 characters
// @param {string} input            - text to hash. By default, it supports the entire range of characters, char(0)-char(65535)
// @param {number} [out_byte_len]   - (optional) byte length of the output hash
// @param {string} [input_encoding] - (optional) format to encode the input string with
// @param {string} [key_encoding]   - (optional) format to encode the secret key with
// @param {string} [hash_encoding]  - (optional) format to encode the output hash with
// @returns {string}                - the hash
// @example minicrypt.BLAKE3.keyedHash("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c", "Hello BLAKE3!")
minicrypt.BLAKE3.keyedHash = function(key, input, out_byte_len = 32, input_encoding = "16bit", key_encoding = "hex", hash_encoding = "hex")
    ie = minicrypt.Encode.getEncoding(input_encoding)
    if ie == null then return minicrypt.Error("minicrypt.BLAKE3.hash", "unsupported_encoding")
    encode = ie[0]

    ke = minicrypt.Encode.getEncoding(key_encoding)
    if ke == null then return minicrypt.Error("minicrypt.BLAKE3.hash", "unsupported_encoding")
    key_encode = ke[0]

    he = minicrypt.Encode.getEncoding(hash_encoding)
    if he == null then return minicrypt.Error("minicrypt.BLAKE3.hash", "unsupported_encoding")
    decode = he[1]

    res = key_encode(key)
    if typeof(res) == "error" then return res
    key_raw = res[0]
    key_len = res[1]
    if key_len != 32 then return minicrypt.Error("minicrypt.BLAKE3.keyedHash", "invalid_key_length")

    res = encode(input)
    if typeof(res) == "error" then return res
    input_raw = res[0]
    input_len = res[1]

    hash_state = minicrypt.BLAKE3.startKeyedHash(key_raw)
    minicrypt.BLAKE3.updateHash(hash_state, input_raw, input_len)
    hash_raw = minicrypt.BLAKE3.finalizeHash(hash_state, ceil(out_byte_len/4))

    hash = decode(hash_raw, out_byte_len)
    return hash
end function

// Hashes an input string using a secret key, returning a 32-byte hex string.
// @param {string} key              - the secret key. By default a hex string, 32 bytes / 64 characters
// @param {string} input            - text to hash. By default, it supports the entire range of characters, char(0)-char(65535)
// @param {number} [out_byte_len]   - (optional) byte length of the output hash
// @param {string} [input_encoding] - (optional) format to encode the input string with
// @param {string} [key_encoding]   - (optional) format to encode the secret key with
// @param {string} [hash_encoding]  - (optional) format to encode the output hash with
// @returns {string}                - the hash
// @example minicrypt.BLAKE3.deriveKey("171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c", "file encryption key for MyCoolApp 2026-10-22 12:53:16")
minicrypt.BLAKE3.deriveKey = function(input, context, out_byte_len = 32, input_encoding = "hex", context_encoding = "8bit", output_encoding = "hex")
    ie = minicrypt.Encode.getEncoding(input_encoding)
    if ie == null then return minicrypt.Error("minicrypt.BLAKE3.hash", "unsupported_encoding")
    encode = ie[0]

    ce = minicrypt.Encode.getEncoding(context_encoding)
    if ce == null then return minicrypt.Error("minicrypt.BLAKE3.hash", "unsupported_encoding")
    context_encode = ce[0]

    oe = minicrypt.Encode.getEncoding(output_encoding)
    if oe == null then return minicrypt.Error("minicrypt.BLAKE3.hash", "unsupported_encoding")
    decode = oe[1]

    res = encode(input)
    if typeof(res) == "error" then return res
    input_raw = res[0]
    input_len = res[1]

    res = context_encode(context)
    if typeof(res) == "error" then return res
    context_raw = res[0]
    context_len = res[1]

    hash_state = minicrypt.BLAKE3.startDeriveKey(context_raw, context_len)
    minicrypt.BLAKE3.updateHash(hash_state, input_raw, input_len)
    key_raw = minicrypt.BLAKE3.finalizeHash(hash_state, ceil(out_byte_len/4))

    key = decode(key_raw, out_byte_len)
    return key
end function

minicrypt.BLAKE3.getHasher = function
    exit("UNIMPLEMENTED")
end function
minicrypt.BLAKE3.getKeyedHasher = function
    exit("UNIMPLEMENTED")
end function

end function //-------------

if not minicrypt.hasIndex("BLAKE3") then __scope()
globals.remove("__scope")