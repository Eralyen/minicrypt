// big integers are stored in little-endian arrays of positive 26-bit numbers
// WARNING: this library is experimental and not fully tested outside of what is explicitly called by another file.
// Use at your own risk.

if not globals.hasIndex("minicrypt") then minicrypt = {}

__scope = function //-------------

minicrypt.BigInt = {}
BigInt = minicrypt.BigInt
BigInt.init = function(bits = 256, W = 26)
    self.W = W
    self.N = ceil(bits / self.W)
    self.BITS = self.W * self.N

    self.MAXVAL1 = 2^self.W
    self.MAXVAL  = self.MAXVAL1 - 1

    self.MASK = [0]
    for i in range(1, self.W)
        self.MASK.push(2^i-1)
    end for

    self.POW2 = []
    for i in range(0, self.W)
        self.POW2.push(2^i)
    end for

    self.INT2HEX = "0123456789abcdef"
    self.HEX2INT = {
        "0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
        "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
        "a": 10, "b": 11, "c": 12, "d": 13, "e": 14, "f": 15,
        "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15,
    }
    
    self.Utils.seed = time * 1000
    self.Utils.MAXVAL1 = self.MAXVAL1
end function

// ----------------- UTILS AND MISC ----------------------------------

BigInt.Utils = {}

// Modulo, but returns a positive integer if a is negative
BigInt.Utils.mod = function(a, m)
    s = a % m
    if a < 0 then s = s + m
    return s
end function

// [first, last)
// not cryptographically secure
BigInt.Utils.random = function(first, last)
    self.seed = floor(rnd(self.seed + 1) * self.MAXVAL1)
    return floor(rnd(self.seed) * (last - first) + first)
end function

BigInt.trim = function(a, length)
    return a[:length]
end function

BigInt.sign = function(a)
    return bitwise(">>", a[-1], self.W-1)
end function

// ----------------- STRING CONVERSIONS ---------------------------------

BigInt.toBinary = function(a)
    b = ""
    for i in range(self.N-1)
        for j in range(self.W-1)
            b = b + char(48 + bitAnd(bitwise(">>", a[i], j), 1))
        end for
    end for
    return "0b" + b
end function

BigInt.fromBinary = function(bin)
    if bin[:2] == "0b" then bin = bin[2:]
    s = self.zero
    while bin != ""
        s = self.lshift(s, 1)
        s[0] = s[0] + (code(bin[-1]) - 48)
        bin = bin[:-1]
    end while
    return s
end function

BigInt.toHex = function(a)
    h = ""
    for i in range(ceil(self.BITS / 4)-1)
        code = bitAnd(self.rshift(a, 4*i)[0], 15)
        h = h + self.INT2HEX[code]
    end for
    return "0x" + h
end function

BigInt.fromHex = function(hex)
    if hex[:2] == "0x" then hex = hex[2:]
    s = self.zero
    while hex != ""
        s = self.lshift(s, 4)
        s[0] = s[0] + self.HEX2INT[hex[-1]]
        hex = hex[:-1]
    end while
    return s
end function

// Base 10
BigInt.toString = function(a)
    str = ""
    zero = self.zero
    x = self.copy(a)
    if self.equals(x, zero) then return "0"
    while self.greaterThan(x, zero)
        res = self.divBy10(x)
        x = res[0]
        str = res[1] + str
    end while
    return str
end function

BigInt.fromString = function(str)
    r = self.zero
    for s in str
        if s < "0" or s > "9" then return null
        x = code(s) - code("0")
        r = self.times10(r)
        r = self.add(r, self.fromSmall(x))
    end for
    return r
end function

// ----------------- BIGINT GENERATORS ----------------------

BigInt.zero = function
    return [0] * self.N
end function

BigInt.one = function
    return [1] + [0] * (self.N - 1)
end function

BigInt.negOne = function
    return [self.MAXVAL] * self.N
end function

BigInt.copy = function(a)
    return a[:]
end function

BigInt.fromSmall = function(n)
    if abs(n) > self.MAXVAL then return null
    s = self.zero
    s[0] = bitAnd(n, self.MAXVAL)
    if s < 0 and self.N > 1 then
        for i in range(0, self.N-1)
            s[i] = self.MAXVAL
        end for
    end if
    return s
end function

// Figure out how to make this cryptographically random
BigInt.random = function
    s = self.zero
    for i in range(0, self.N-1)
        s[i] = self.Utils.random(0, self.MAXVAL1)
    end for
    return s
end function

BigInt.pow2 = function(n)
    r = n % 26
    q = (n - r) / 26
    bi = self.zero
    if q < self.N then bi[q] = self.POW2[r]
    return bi
end function

// --------------------- COMPARISONS ------------------

// Constant time
BigInt.cmp = function(a, b, signed = true)
    if signed then
        sa = self.sign(a)
        sb = self.sign(b)
        if sa == 0 and sb == 1 then return 1
        if sa == 1 and sb == 0 then return -1
    end if
    for i in range(self.N-1)
        if a[i] > b[i] then
            return 1
        else if a[i] < b[i] then
            return -1
        end if
    end for
    return 0
end function

BigInt.equals = function(a, b, signed = true)
    return self.cmp(a, b, signed) == 0
end function

BigInt.greaterThan = function(a, b, signed = true)
    return self.cmp(a, b, signed) == 1
end function

BigInt.lessThan = function(a, b, signed = true)
    return self.cmp(a, b, signed) == -1
end function

BigInt.greaterOrEqual = function(a, b, signed = true)
    return self.cmp(a, b, signed) >= 0
end function

BigInt.lessOrEqual = function(a, b, signed = true)
    return self.cmp(a, b, signed) <= 0
end function

BigInt.isEven = function(a)
    return not bitAnd(a[0], 1)
end function

// --------------------- BITWISE OPERATIONS ---------------------
// Logical right shift
BigInt.rshift = function(a, n)
    s = self.zero
    bit_rshift = n % self.W
    bit_lshift = self.W - bit_rshift
    word_shift = floor(n / self.W)
    if word_shift >= a.len then return self.zero
    for i in range(0, a.len - word_shift - 1)
        s[i] = bitwise(">>", a[i + word_shift], bit_rshift)
        if i + word_shift + 1 < a.len and bit_rshift != 0 then
            s[i] = s[i] + bitwise("<<", bitAnd(a[i + word_shift + 1], self.MASK[bit_rshift]), bit_lshift)
        end if
    end for
    return s
end function

// Logical left shift
BigInt.lshift = function(a, n)
    s = self.zero
    bit_lshift = n % self.W
    bit_rshift = self.W - bit_lshift
    word_shift = floor(n / self.W)
    if word_shift >= a.len then return self.zero
    for i in range(a.len - 1, word_shift)
        s[i] = bitwise("<<", bitAnd(a[i - word_shift], self.MASK[bit_rshift]), bit_lshift)
        if i > word_shift and bit_lshift != 0 then
            s[i] = s[i] + bitwise(">>", a[i - word_shift - 1], bit_rshift)
        end if
    end for
    return s
end function

// Arithmetic right shift
BigInt.arshift = function(a, n)
    sign = self.sign(a)
    if sign == 0 then
        s = self.zero
    else
        s = self.negOne
    end if
    bit_rshift = n % self.W
    bit_lshift = self.W - bit_rshift
    word_shift = floor(n / self.W)
    if word_shift >= a.len then return self.zero
    for i in range(0, a.len - word_shift - 1)
        s[i] = bitwise(">>", a[i + word_shift], bit_rshift)
        if i + word_shift + 1 < a.len then
            if bit_rshift != 0 then s[i] = s[i] + bitwise("<<", bitAnd(a[i + word_shift + 1], self.MASK[bit_rshift]), bit_lshift)
        else if sign == 1 then
            s[i] = s[i] + bitwise("<<", self.MASK[bit_rshift], bit_lshift)
        end if
    end for
    return s
end function

BigInt.bitAnd = function(a, b)
    s = self.zero
    for i in range(0, self.N-1)
        s[i] = bitAnd(a[i], b[i])
    end for
    return s
end function

// --------------------- CLASSICAL OPERATIONS -------------------

BigInt.add = function(a, b, ret_carry = false)
    s = self.zero
    carry = 0
    for i in range(0, self.N-1)
        x = a[i] + b[i] + carry
        s[i] = bitAnd(x, self.MAXVAL)
        carry = bitwise(">>", x, self.W)
    end for
    if ret_carry then return [s, carry]
    return s
end function

BigInt.sub = function(a, b, ret_carry = false)
    s = self.zero
    carry = 0
    for i in range(0, self.N-1)
        x = a[i] - b[i] - carry
        if x < 0 then
            x = x + self.MAXVAL1
            carry = 1
        else
            carry = 0
        end if
        s[i] = bitAnd(x, self.MAXVAL)
    end for
    if ret_carry then return [s, ret_carry]
    return s
end function

BigInt.mult = function(a, b, trim = true)
    s = [0] * (self.N * 2)
    for i in range(0, self.N-1)
        carry = 0
        for j in range(0, self.N-1)
            x = s[i+j] + a[j] * b[i] + carry
            carry = floor(x / self.MAXVAL1)
            s[i+j] = x % self.MAXVAL1
        end for
        s[i + self.N] = carry
    end for
    if trim then s = s[:self.N]
    return s
end function

// ----------------------- MODULAR OPERATIONS ------------
// a < m, b < m, a >= 0, b >= 0, m > 0

// s = -a mod m
BigInt.modNeg = function(a, m)
    return self.sub(m, a)
end function

BigInt.modAdd = function(a, b, m)
    s = self.add(a, b)
    if self.greaterOrEqual(s, m, false) then
        s = self.sub(s, m)
    end if
    return s
end function

BigInt.modSub = function(a, b, m)
    if self.lessThan(a, b, false) then
        a = self.add(a, m)
    end if
    s = self.sub(a, b)
    return s
end function

// Warning: p needs to be 2*BigInt.N elements long
BigInt.multP = function(a, b, t, c, p)
    x = self.mult(a, b, false)
    x = self.specMod(x, t, c, p)
    return x[:self.N]
end function

// Multiplicative inverse: finds x such that a*x = 1 mod p where p is prime
// 1 <= a < p
BigInt.invertP = function(a, p)
    u = self.copy(a)
    v = self.copy(p)
    x1 = self.one
    x2 = self.zero
    while not self.equals(u, self.one) and not self.equals(v, self.one)
        while self.isEven(u)
            u = self.arshift(u, 1)
            if self.isEven(x1) then
                x1 = self.arshift(x1, 1)
            else
                x1 = self.arshift(self.add(x1, p), 1)
            end if
        end while
        while self.isEven(v)
            v = self.arshift(v, 1)
            if self.isEven(x2) then
                x2 = self.arshift(x2, 1)
            else
                x2 = self.arshift(self.add(x2, p), 1)
            end if
        end while
        if self.greaterOrEqual(u, v) then
            u  = self.sub(u, v)
            x1 = self.sub(x1, x2)
        else
            v  = self.sub(v, u)
            x2 = self.sub(x2, x1)
        end if
    end while
    if self.equals(u, self.one) then
        x = x1
    else
        x = x2
    end if
    while self.greaterOrEqual(x, p)
        x = self.sub(x, p)
    end while
    return x
end function

// Division: finds x such that a/b = a*b^-1 = x mod p where p is prime
// 1 <= a < p
// 1 <= b < p
BigInt.divP = function(a, b, p)
    u = self.copy(b)
    v = self.copy(p)
    x1 = self.copy(a)
    x2 = self.zero
    while not self.equals(u, self.one) and not self.equals(v, self.one)
        while self.isEven(u)
            u = self.arshift(u, 1)
            if self.isEven(x1) then
                x1 = self.arshift(x1, 1)
            else
                x1 = self.arshift(self.add(x1, p), 1)
            end if
        end while
        while self.isEven(v)
            v = self.arshift(v, 1)
            if self.isEven(x2) then
                x2 = self.arshift(x2, 1)
            else
                x2 = self.arshift(self.add(x2, p), 1)
            end if
        end while
        if self.greaterOrEqual(u, v) then
            u  = self.sub(u, v)
            x1 = self.sub(x1, x2)
        else
            v  = self.sub(v, u)
            x2 = self.sub(x2, x1)
        end if
    end while
    if self.equals(u, self.one) then
        x = x1
    else
        x = x2
    end if
    while self.greaterOrEqual(x, p)
        x = self.sub(x, p)
    end while
    return x
end function

// ----------------------SPECIAL OPERATIONS-------------

// Special, fast modular reduction in the form of x = y mod p, where p = (b^t - c), and b = BigInt.MAXVAL1
// Adapted from the Handbook of Applied Cryptography by A.Menzenes, p.605
BigInt.specMod = function(x, t, c, p)
    div = self.divByWords(x, t)
    q = div[0]
    r = div[1]
    y = self.copy(r)
    zero = self.zero
    while self.greaterThan(q, zero, false)
        div = self.divByWords(self.mult(q, self.fromSmall(c), true), t)
        q = div[0]
        r = div[1]
        y = self.add(y, r)
    end while
    while self.greaterOrEqual(y, p, false)
        y = self.sub(y, p)
    end while
    return y
end function

BigInt.times10 = function(x)
    a = self.lshift(x, 3) // Times 8
    b = self.lshift(x, 1) // Times 2
    return self.add(a, b)
end function

BigInt.divBy10 = function(a)
    q = self.zero
    carry = 0
    for i in range(self.N-1)
        x = self.MAXVAL1 * carry + a[i]
        q[i] = floor(x / 10)
        carry = x % 10
    end for
    return [q, carry]
end function

// [quotient, remainder] = x / b^t where b = BigInt.MAXVAL1 (the base for one word)
BigInt.divByWords = function(x, t)
    r = x[:t] + [0] * (x.len - t)
    q = x[t:] + [0] * t
    return [q, r]
end function

end function //-------------

if not minicrypt.hasIndex("BigInt") then __scope()
globals.remove("__scope")