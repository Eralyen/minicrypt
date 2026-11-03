globals.isGH = true
import_code("./MiniTest/MiniTest.src")
import_code("../src/x25519.ms")

X25519 = minicrypt.X25519

// Representation: 16 limbs of 16 bits (radix 2^16), arithmetic mod 2^255 - 19.
// mul / square write only w[0..15]; any extra elements of w are left alone,
// so these tests start from a 32-element "junk" array (all 7s) on purpose.
// Results are loosely reduced (limbs 1..15 in 0..65535), not necessarily < p.

test_field = function
    u = [1, 2] + [0] * 14
    v = [3, 4] + [0] * 14
    product = [7] * 32
    expected = [3, 10, 8] + [0] * 13

    X25519.mul(product, u, v)
    expectEqual(product[:16], expected, "(1 + 2x)(3 + 4x) = 3 + 10x + 8x^2")
    expectEqual(product[16:], [7] * 16, "mul only writes w[0..15]")

    u = [1, 2, 3, 4, 5] + [0] * 11
    square = [7] * 32
    expected = [1, 4, 10, 20, 35, 44, 46, 40, 25] + [0] * 7

    X25519.square(square, u)
    expectEqual(square[:16], expected, "Square computes each coefficient")
    expectEqual(square[16:], [7] * 16, "square only writes w[0..15]")

    u = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    v = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]
    result = [0] * 16

    X25519.add(result, u, v)
    expectEqual(result, [12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42])

    X25519.sub(result, v, u)
    expectEqual(result, [10] * 16, "sub returns v - u")

    // 2^256 = 38 (mod 2^255 - 19), so x^16 folds to 38 in limb 0
    x15 = [0] * 15 + [1]
    x1 = [0, 1] + [0] * 14
    result = [7] * 32

    X25519.mul(result, x15, x1)
    expectEqual(result[:16], [38] + [0] * 15, "x^15 * x = x^16 folds to 38")

    // x^30 = x^14 * x^16 -> 38 in limb 14
    X25519.mul(result, x15, x15)
    expected = [0] * 14 + [38, 0]
    expectEqual(result[:16], expected, "x^15 * x^15 folds to 38 * x^14")

    X25519.square(result, x15)
    expectEqual(result[:16], expected, "square(x^15) matches the mul result")

    result = [7] * 32

    // 300 * 1000 = 300000 = 4 * 65536 + 37856
    X25519.mul(result, [300] + [0] * 15, [1000] + [0] * 15)
    expectEqual(result[:16], [37856, 4] + [0] * 14, "Overflow carries into the next limb")

    // 65535 * (1 + x) * 65535 = 65535^2 + 65535^2 * x, carries ripple upward
    X25519.mul(result, [65535, 65535] + [0] * 14, [65535] + [0] * 15)
    expectEqual(result[:16], [1, 65535, 65534] + [0] * 13, "Carries ripple through several limbs")

    // Carry out of limb 15 wraps around into limb 0 multiplied by 38
    X25519.mul(result, [0] * 15 + [65535], [2] + [0] * 15)
    expectEqual(result[:16], [38] + [0] * 14 + [65534], "Carry out of the top limb folds into limb 0")

    // Negative limbs (as produced by sub) are carried correctly:
    // -1 = 2p - 1 = 2^256 - 39 (mod p), i.e. limb 0 = 65497, all others 65535
    X25519.mul(result, [-1] + [0] * 15, [1] + [0] * 15)
    expectEqual(result[:16], [65497] + [65535] * 15, "Negative limbs borrow from higher limbs")

    result = [7] * 32

    // All limbs 65535 is 2^256 - 1, which is 37 (mod p); 37^2 = 1369
    all_ones = [65535] * 16
    X25519.square(result, all_ones)
    expectEqual(result[:16], [1369] + [0] * 15, "square of 2^256 - 1 is 37^2 mod p")

    X25519.mul(result, all_ones, all_ones)
    expectEqual(result[:16], [1369] + [0] * 15, "mul of 2^256 - 1 with itself matches square")

    // Exact integer arithmetic, no wraparound involved
    u = [65535, 0, 65535, 0, 65535] + [0] * 11
    expected = [1, 65534, 2, 65532, 4, 65530, 4, 65532, 2, 65534] + [0] * 6
    X25519.square(result, u)
    expectEqual(result[:16], expected, "square matches exact integer arithmetic")

    // The output may be the same array as either input
    u = [1, 2] + [0] * 14
    v = [3, 4] + [0] * 14
    X25519.mul(u, u, v)
    expectEqual(u, [3, 10, 8] + [0] * 13, "mul(u, u, v)")

    u = [1, 2] + [0] * 14
    v = [3, 4] + [0] * 14
    X25519.mul(v, u, v)
    expectEqual(v, [3, 10, 8] + [0] * 13, "mul(v, u, v)")

    u = [1, 2, 3, 4, 5] + [0] * 11
    X25519.square(u, u)
    expectEqual(u, [1, 4, 10, 20, 35, 44, 46, 40, 25] + [0] * 7, "square(u, u)")

    // p = 2^255 - 19
    p = [65517] + [65535] * 14 + [32767]
    result = [7] * 32

    X25519.freeze(result, p)
    expectEqual(result[:16], [0] * 16, "p freezes to zero")
    expectEqual(result[16:], [7] * 16, "freeze only writes w[0..15]")

    p_plus_one = [65518] + [65535] * 14 + [32767]
    X25519.freeze(result, p_plus_one)
    expectEqual(result[:16], [1] + [0] * 15, "p + 1 freezes to one")

    // 2p + 1 = 2^256 - 37, the largest loosely reduced form of one
    X25519.freeze(result, [65499] + [65535] * 15)
    expectEqual(result[:16], [1] + [0] * 15, "2p + 1 freezes to one")

    // 2^256 - 1 = 37 (mod p)
    X25519.freeze(result, [65535] * 16)
    expectEqual(result[:16], [37] + [0] * 15, "2^256 - 1 freezes to 37")

    // p - 1 is already canonical and must not change
    p_minus_one = [65516] + [65535] * 14 + [32767]
    X25519.freeze(result, p_minus_one)
    expectEqual(result[:16], p_minus_one, "p - 1 is unchanged")

    small = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] + [0] * 6
    X25519.freeze(result, small)
    expectEqual(result[:16], small, "small values are unchanged")

    // Negative limbs (as produced by sub): -1 = p - 1
    X25519.freeze(result, [-1] + [0] * 15)
    expectEqual(result[:16], p_minus_one, "-1 freezes to p - 1")

    // Output may alias the input
    x = [65499] + [65535] * 15
    X25519.freeze(x, x)
    expectEqual(x, [1] + [0] * 15, "freeze(x, x) works in place")

    value = [2] + [0] * 15
    inverse = [7] * 32
    product = [7] * 32
    one = [1] + [0] * 15

    X25519.invert(inverse, value)
    X25519.mul(product, value, inverse)
    X25519.freeze(product, product)
    expectEqual(product[:16], one, "a multiplied by its inverse is one")

    // 1/2 = (p + 1) / 2 = 2^254 - 9
    X25519.freeze(inverse, inverse)
    expected = [65527] + [65535] * 14 + [16383]
    expectEqual(inverse[:16], expected, "the inverse of two is (p + 1) / 2")

    // In-place inversion
    x = [2] + [0] * 15
    X25519.invert(x, x)
    X25519.mul(product, [2] + [0] * 15, x)
    X25519.freeze(product, product)
    expectEqual(product[:16], one, "invert(x, x) works in place")

    // Conditional swap
    p = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] + [7] * 16
    q = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116] + [8] * 16
    p_orig = p[:]
    q_orig = q[:]

    X25519.cswap(p, q, 0)
    expectEqual(p, p_orig, "b = 0 leaves p unchanged")
    expectEqual(q, q_orig, "b = 0 leaves q unchanged")

    X25519.cswap(p, q, 1)
    expectEqual(p[:16], q_orig[:16], "b = 1 moves q into p")
    expectEqual(q[:16], p_orig[:16], "b = 1 moves p into q")
    expectEqual(p[16:], [7] * 16, "cswap only touches elements 0..15")
    expectEqual(q[16:], [8] * 16, "cswap only touches elements 0..15")

    // Works with negative limbs (as produced by sub)
    p = [-5] + [0] * 15
    q = [65535] + [0] * 15
    X25519.cswap(p, q, 1)
    expectEqual(p, [65535] + [0] * 15)
    expectEqual(q, [-5] + [0] * 15)
end function
TEST "X25519 - Field", @test_field


// ---- helpers for test_curve -------------------------------------------------
// Hex strings are little-endian byte strings, exactly as written in RFC 7748.
// 64 hex chars (32 bytes) <-> 16 limbs of 16 bits; limb j = byte[2j] + 256 * byte[2j+1].
hexToLimbs = function(hexString)
    digits = "0123456789abcdef"
    limbs = []
    for j in range(0, 15)
        lo = digits.indexOf(hexString[4*j]) * 16 + digits.indexOf(hexString[4*j + 1])
        hi = digits.indexOf(hexString[4*j + 2]) * 16 + digits.indexOf(hexString[4*j + 3])
        limbs.push lo + hi * 256
    end for
    return limbs
end function

limbsToHex = function(limbs)
    digits = "0123456789abcdef"
    result = ""
    for limb in limbs
        lo = limb % 256
        hi = (limb - lo) / 256
        result = result + digits[(lo - lo % 16) / 16] + digits[lo % 16]
        result = result + digits[(hi - hi % 16) / 16] + digits[hi % 16]
    end for
    return result
end function

// X25519(scalar, u) on hex strings.
x25519Hex = function(scalarHex, uHex)
    q = [7] * 16
    X25519.scalarMult(q, hexToLimbs(scalarHex), hexToLimbs(uHex))
    return limbsToHex(q[:16])
end function

// Test vectors: RFC 7748 (sections 5.2 and 6.1). Each was also checked against an
// independent bigint implementation of the RFC ladder and against the Python
// "cryptography" library (OpenSSL X25519).
test_curve = function
    basePoint = "09" + "00" * 31

    // Helper sanity: round trip
    hex = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    expectEqual(limbsToHex(hexToLimbs(hex)), hex, "hex <-> limbs round trip")
    expectEqual(hexToLimbs(basePoint), [9] + [0] * 15, "u = 9 as limbs")

    // RFC 7748 section 5.2, first test vector
    expectEqual(x25519Hex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        "RFC 7748 5.2 vector 1")

    // RFC 7748 section 5.2, second test vector.
    // The u-coordinate's top bit (bit 255) is set, and X25519 must ignore it.
    expectEqual(x25519Hex(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        "RFC 7748 5.2 vector 2 (u-coordinate with bit 255 set)")

    // RFC 7748 section 5.2, iterated test, after 1 iteration (k = u = 9).
    // The 1,000 and 1,000,000 iteration results are skipped: far too many scalar multiplications.
    expectEqual(x25519Hex(basePoint, basePoint),
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        "RFC 7748 5.2 iterated, 1 iteration")

    // RFC 7748 section 6.1, Diffie-Hellman
    alicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    bobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    bobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    expectEqual(x25519Hex(alicePrivate, basePoint), alicePublic, "Alice's public key")
    expectEqual(x25519Hex(bobPrivate, basePoint), bobPublic, "Bob's public key")
    expectEqual(x25519Hex(alicePrivate, bobPublic), shared, "shared secret (Alice's side)")
    expectEqual(x25519Hex(bobPrivate, alicePublic), shared, "shared secret (Bob's side)")

    // scalarMult must not modify its inputs
    n = hexToLimbs(alicePrivate)
    p = hexToLimbs(bobPublic)
    q = [7] * 32
    X25519.scalarMult(q, n, p)
    expectEqual(n, hexToLimbs(alicePrivate), "scalarMult leaves the scalar unchanged")
    expectEqual(p, hexToLimbs(bobPublic), "scalarMult leaves the point unchanged")
    expectEqual(q[16:], [7] * 16, "scalarMult only writes q[0..15]")
end function
TEST "X25519 - Scalar multiplication & DH", @test_curve


if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if
