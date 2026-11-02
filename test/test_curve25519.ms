globals.isGH = true
import_code("./MiniTest/MiniTest.src")
import_code("../src/curve25519/field.ms")

Field25519 = minicrypt.Field25519

// Representation: 16 limbs of 16 bits (radix 2^16), arithmetic mod 2^255 - 19.
// mul / square write only w[0..15]; any extra elements of w are left alone,
// so these tests start from a 32-element "junk" array (all 7s) on purpose.
// Results are loosely reduced (limbs 1..15 in 0..65535), not necessarily < p.

test_field = function
    u = [1, 2] + [0] * 14
    v = [3, 4] + [0] * 14
    product = [7] * 32
    expected = [3, 10, 8] + [0] * 13

    Field25519.mul(product, u, v)
    expectEqual(product[:16], expected, "(1 + 2x)(3 + 4x) = 3 + 10x + 8x^2")
    expectEqual(product[16:], [7] * 16, "mul only writes w[0..15]")

    u = [1, 2, 3, 4, 5] + [0] * 11
    square = [7] * 32
    expected = [1, 4, 10, 20, 35, 44, 46, 40, 25] + [0] * 7

    Field25519.square(square, u)
    expectEqual(square[:16], expected, "Square computes each coefficient")
    expectEqual(square[16:], [7] * 16, "square only writes w[0..15]")

    u = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    v = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]
    result = [0] * 16

    Field25519.add(result, u, v)
    expectEqual(result, [12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42])

    Field25519.sub(result, v, u)
    expectEqual(result, [10] * 16, "sub returns v - u")

    // 2^256 = 38 (mod 2^255 - 19), so x^16 folds to 38 in limb 0
    x15 = [0] * 15 + [1]
    x1 = [0, 1] + [0] * 14
    result = [7] * 32

    Field25519.mul(result, x15, x1)
    expectEqual(result[:16], [38] + [0] * 15, "x^15 * x = x^16 folds to 38")

    // x^30 = x^14 * x^16 -> 38 in limb 14
    Field25519.mul(result, x15, x15)
    expected = [0] * 14 + [38, 0]
    expectEqual(result[:16], expected, "x^15 * x^15 folds to 38 * x^14")

    Field25519.square(result, x15)
    expectEqual(result[:16], expected, "square(x^15) matches the mul result")

    result = [7] * 32

    // 300 * 1000 = 300000 = 4 * 65536 + 37856
    Field25519.mul(result, [300] + [0] * 15, [1000] + [0] * 15)
    expectEqual(result[:16], [37856, 4] + [0] * 14, "Overflow carries into the next limb")

    // 65535 * (1 + x) * 65535 = 65535^2 + 65535^2 * x, carries ripple upward
    Field25519.mul(result, [65535, 65535] + [0] * 14, [65535] + [0] * 15)
    expectEqual(result[:16], [1, 65535, 65534] + [0] * 13, "Carries ripple through several limbs")

    // Carry out of limb 15 wraps around into limb 0 multiplied by 38
    Field25519.mul(result, [0] * 15 + [65535], [2] + [0] * 15)
    expectEqual(result[:16], [38] + [0] * 14 + [65534], "Carry out of the top limb folds into limb 0")

    // Negative limbs (as produced by sub) are carried correctly:
    // -1 = 2p - 1 = 2^256 - 39 (mod p), i.e. limb 0 = 65497, all others 65535
    Field25519.mul(result, [-1] + [0] * 15, [1] + [0] * 15)
    expectEqual(result[:16], [65497] + [65535] * 15, "Negative limbs borrow from higher limbs")

    result = [7] * 32

    // All limbs 65535 is 2^256 - 1, which is 37 (mod p); 37^2 = 1369
    all_ones = [65535] * 16
    Field25519.square(result, all_ones)
    expectEqual(result[:16], [1369] + [0] * 15, "square of 2^256 - 1 is 37^2 mod p")

    Field25519.mul(result, all_ones, all_ones)
    expectEqual(result[:16], [1369] + [0] * 15, "mul of 2^256 - 1 with itself matches square")

    // Exact integer arithmetic, no wraparound involved
    u = [65535, 0, 65535, 0, 65535] + [0] * 11
    expected = [1, 65534, 2, 65532, 4, 65530, 4, 65532, 2, 65534] + [0] * 6
    Field25519.square(result, u)
    expectEqual(result[:16], expected, "square matches exact integer arithmetic")

    // The output may be the same array as either input
    u = [1, 2] + [0] * 14
    v = [3, 4] + [0] * 14
    Field25519.mul(u, u, v)
    expectEqual(u, [3, 10, 8] + [0] * 13, "mul(u, u, v)")

    u = [1, 2] + [0] * 14
    v = [3, 4] + [0] * 14
    Field25519.mul(v, u, v)
    expectEqual(v, [3, 10, 8] + [0] * 13, "mul(v, u, v)")

    u = [1, 2, 3, 4, 5] + [0] * 11
    Field25519.square(u, u)
    expectEqual(u, [1, 4, 10, 20, 35, 44, 46, 40, 25] + [0] * 7, "square(u, u)")

    // p = 2^255 - 19
    p = [65517] + [65535] * 14 + [32767]
    result = [7] * 32

    Field25519.freeze(result, p)
    expectEqual(result[:16], [0] * 16, "p freezes to zero")
    expectEqual(result[16:], [7] * 16, "freeze only writes w[0..15]")

    p_plus_one = [65518] + [65535] * 14 + [32767]
    Field25519.freeze(result, p_plus_one)
    expectEqual(result[:16], [1] + [0] * 15, "p + 1 freezes to one")

    // 2p + 1 = 2^256 - 37, the largest loosely reduced form of one
    Field25519.freeze(result, [65499] + [65535] * 15)
    expectEqual(result[:16], [1] + [0] * 15, "2p + 1 freezes to one")

    // 2^256 - 1 = 37 (mod p)
    Field25519.freeze(result, [65535] * 16)
    expectEqual(result[:16], [37] + [0] * 15, "2^256 - 1 freezes to 37")

    // p - 1 is already canonical and must not change
    p_minus_one = [65516] + [65535] * 14 + [32767]
    Field25519.freeze(result, p_minus_one)
    expectEqual(result[:16], p_minus_one, "p - 1 is unchanged")

    small = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] + [0] * 6
    Field25519.freeze(result, small)
    expectEqual(result[:16], small, "small values are unchanged")

    // Negative limbs (as produced by sub): -1 = p - 1
    Field25519.freeze(result, [-1] + [0] * 15)
    expectEqual(result[:16], p_minus_one, "-1 freezes to p - 1")

    // Output may alias the input
    x = [65499] + [65535] * 15
    Field25519.freeze(x, x)
    expectEqual(x, [1] + [0] * 15, "freeze(x, x) works in place")

    value = [2] + [0] * 15
    inverse = [7] * 32
    product = [7] * 32
    one = [1] + [0] * 15

    Field25519.invert(inverse, value)
    Field25519.mul(product, value, inverse)
    Field25519.freeze(product, product)
    expectEqual(product[:16], one, "a multiplied by its inverse is one")

    // 1/2 = (p + 1) / 2 = 2^254 - 9
    Field25519.freeze(inverse, inverse)
    expected = [65527] + [65535] * 14 + [16383]
    expectEqual(inverse[:16], expected, "the inverse of two is (p + 1) / 2")

    // In-place inversion
    x = [2] + [0] * 15
    Field25519.invert(x, x)
    Field25519.mul(product, [2] + [0] * 15, x)
    Field25519.freeze(product, product)
    expectEqual(product[:16], one, "invert(x, x) works in place")

    // Conditional swap
    p = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] + [7] * 16
    q = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116] + [8] * 16
    p_orig = p[:]
    q_orig = q[:]

    Field25519.cswap(p, q, 0)
    expectEqual(p, p_orig, "b = 0 leaves p unchanged")
    expectEqual(q, q_orig, "b = 0 leaves q unchanged")

    Field25519.cswap(p, q, 1)
    expectEqual(p[:16], q_orig[:16], "b = 1 moves q into p")
    expectEqual(q[:16], p_orig[:16], "b = 1 moves p into q")
    expectEqual(p[16:], [7] * 16, "cswap only touches elements 0..15")
    expectEqual(q[16:], [8] * 16, "cswap only touches elements 0..15")

    // Works with negative limbs (as produced by sub)
    p = [-5] + [0] * 15
    q = [65535] + [0] * 15
    Field25519.cswap(p, q, 1)
    expectEqual(p, [65535] + [0] * 15)
    expectEqual(q, [-5] + [0] * 15)
end function
TEST "CURVE25519 - Field", @test_field


if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if
