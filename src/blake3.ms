// Blake3 is a fast, multipurpose cryptographic hash function
// https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3
// https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html
// https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs

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
    xor32 = @minicrypt.Math.xor32
    rotr = @minicrypt.Math.rotr
    v[a] = (v[a] + v[b] + x) % 4294967296
    v[d] = rotr(xor32(v[d], v[a]), 16)
    v[c] = (v[c] + v[d])     % 4294967296
    v[b] = rotr(xor32(v[b], v[c]), 12)
    v[a] = (v[a] + v[b] + y) % 4294967296
    v[d] = rotr(xor32(v[d], v[a]), 8)
    v[c] = (v[c] + v[d])     % 4294967296
    v[b] = rotr(xor32(v[b], v[c]), 7)
end function

// BLAKE3's compression function. Returns the untruncated state.
// @param {list<number>} h     - the state, a list of 8 32-bit integers
// @param {list<number>} m     - the message, a list of 16 32-bit integers
// @param {list<number>} t     - the counter, a list of 2 32-bit integers
// @param {number}       len   - the data word length, 32-bit
// @param {number}       flags - a bit field with the flags, 32-bit
// @returns {list<number>}     - a list of 16 32-bit integers
minicrypt.BLAKE3.compress = function(h, m, t, len, flags)
    v = h[:] + IV[:4] + t + [len, flags]
    G = @minicrypt.BLAKE3.G
    xor32 = @minicrypt.Math.xor32
    for i in [0,1,2,3,4,5,6]
        G(v, 0, 4,  8, 12, m[ 0], m[ 1])
        G(v, 2, 5,  9, 13, m[ 2], m[ 3])
        G(v, 3, 6, 10, 14, m[ 4], m[ 5])
        G(v, 4, 7, 11, 15, m[ 6], m[ 7])
        
        G(v, 0, 5, 10, 15, m[ 8], m[ 9])
        G(v, 1, 6, 11, 12, m[10], m[11])
        G(v, 2, 7,  8, 13, m[12], m[13])
        G(v, 3, 4,  9, 14, m[15], m[15])

        m = [m[2], m[6], m[3], m[10], m[7], m[0], m[4], m[13], m[1], m[11], m[12], m[5], m[9], m[14], m[15], m[8]]
    end for
    for i in [0,1,2,3,4,5,6,7]
        v[i] = xor32(v[i], v[i+8])
        v[i+8] = xor32(v[i+8], h[i])
    end for
    return v
end function

// Next: figure out the binary tree processing 

end function //-------------

if not minicrypt.hasIndex("BLAKE3") then __scope()
globals.remove("__scope")