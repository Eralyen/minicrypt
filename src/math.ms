// Module to store handy math functions

if not globals.hasIndex("minicrypt") then minicrypt = {}

__scope = function //-------------

minicrypt.Math = {}
minicrypt.Math.POW2 = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888, 1099511627776, 2199023255552, 4398046511104, 8796093022208, 17592186044416, 35184372088832, 70368744177664, 140737488355328, 281474976710656, 562949953421312, 1125899906842624, 2251799813685248, 4503599627370496]

// Performs a xor on a and b, 32 bit integers. Native xor only supports 31 bits...
// @param {number} a
// @param {number} b
// @returns {number}
minicrypt.Math.xor32 = function(a, b)
    a_btm   = a % 2147483648 //2^31
    b_btm   = b % 2147483648
    xor_top = (a - a_btm != b - b_btm) * 2147483648
    return xor_top + bitXor(a_btm, b_btm)
end function

// Rotate left (any overflow pops in from the right) a 32-bit value, using faster arithmetic functions
// @param {number}   a - 32-bit value to rotate
// @param {number}   b - rotation amount. Can be any safe integer
// @returns {number}   - rotated value
minicrypt.Math.rotl = function(a, b)
    shl = minicrypt.Math.POW2[b]
    shr = minicrypt.Math.POW2[32-b]
    low = a % shr
    high = a - low
    return low * shl + high / shr
end function

// Rotate right (any overflow pops in from the left) a 32-bit value, using faster arithmetic functions
// @param {number}   a - 32-bit value to rotate
// @param {number}   b - rotation amount. Can be any safe integer
// @returns {number}   - rotated value
minicrypt.Math.rotr = function(a, b)
    shl = minicrypt.Math.POW2[32-b]
    shr = minicrypt.Math.POW2[b]
    low = a % shr
    high = a - low
    return low * shl + high / shr
end function

end function //-------------

if not minicrypt.hasIndex("Math") then __scope()
globals.remove("__scope")