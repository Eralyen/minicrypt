if not globals.hasIndex("minicrypt") then minicrypt = {}

__scope = function //-------------

minicrypt.Encode = {}

minicrypt.Encode.INT2B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
minicrypt.Encode.B642INT = {"A":0,"B":1,"C":2,"D":3,"E":4,"F":5,"G":6,"H":7,"I":8,"J":9,"K":10,"L":11,"M":12,"N":13,"O":14,"P":15,"Q":16,"R":17,"S":18,"T":19,"U":20,"V":21,"W":22,"X":23,"Y":24,"Z":25,"a":26,"b":27,"c":28,"d":29,"e":30,"f":31,"g":32,"h":33,"i":34,"j":35,"k":36,"l":37,"m":38,"n":39,"o":40,"p":41,"q":42,"r":43,"s":44,"t":45,"u":46,"v":47,"w":48,"x":49,"y":50,"z":51,"0":52,"1":53,"2":54,"3":55,"4":56,"5":57,"6":58,"7":59,"8":60,"9":61,"+":62,"/":63}
minicrypt.Encode.INT2HEX = "0123456789abcdef"
minicrypt.Encode.HEX2INT = {
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
    "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
    "a": 10, "b": 11, "c": 12, "d": 13, "e": 14, "f": 15,
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15,
}
minicrypt.Encode.POW2 = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888, 1099511627776, 2199023255552, 4398046511104, 8796093022208, 17592186044416, 35184372088832, 70368744177664, 140737488355328, 281474976710656, 562949953421312, 1125899906842624, 2251799813685248, 4503599627370496]


// Takes a string and returns a list of 32-bit numbers
minicrypt.Encode.encodeText16 = function(text)
    output = []
    if text.len == 0 then return [output, 0]
    for i in range(0, text.len - 1, 2)
        c1 = code(text[i])
        c2 = 0
        if i + 1 < text.len then c2 = code(text[i+1])
        output.push(c2 * 65536 + c1)
    end for
    return [output, text.len*2]
end function

// Takes a string and returns a list of 32-bit numbers
minicrypt.Encode.encodeText8 = function(text)
    output = []
    if text.len == 0 then return output
    for i in range(0, text.len - 1, 4)
        c1 = code(text[i])
        c2 = 0
        c3 = 0
        c4 = 0
        if i + 1 < text.len then c2 = code(text[i+1])
        if i + 2 < text.len then c3 = code(text[i+2])
        if i + 3 < text.len then c4 = code(text[i+3])
        output.push(c4 * 16777216 + c3 * 65536 + c2 * 256 + c1)
    end for
    return [output, text.len]
end function

// Takes a list of 32-bit numbers and returns a string
minicrypt.Encode.decodeText16 = function(input, len)
    text = ""
    if input.len != ceil(len/4) then return minicrypt.Error("minicrypt.Encode.decodeText16", "length_mismatch")
    if input.len == 0 then return ""
    for i in range(0, input.len-1)
        n_low = input[i] % 65536
        n_high = floor(input[i] / 65536)
        if n_high >= 55296 and n_high <= 57343 then return minicrypt.Error("minicrypt.Encode.decodeText16", "invalid_char")
        if n_low  >= 55296 and n_low  <= 57343 then return minicrypt.Error("minicrypt.Encode.decodeText16", "invalid_char")
        text = text + char(n_low)
        if i < input.len-1 or (i == input.len-1 and ceil(len/2) % 2 == 0) then text = text + char(n_high)
    end for
    return text
end function

// Takes a list of 32-bit numbers and returns a string
minicrypt.Encode.decodeText8 = function(input, len)
    text = ""
    if input.len != ceil(len/4) then return minicrypt.Error("minicrypt.Encode.decodeText8", "length_mismatch")
    if input.len == 0 then return ""
    for i in range(0, len-1, 4)
        n = input[i/4]
        n0 = n % 256 ; n = (n - n0) / 256
        n1 = n % 256 ; n = (n - n1) / 256
        n2 = n % 256 ; n = (n - n2) / 256
        n3 = n % 256 ; n = (n - n3) / 256
        text = text + char(n0)
        if i+1 < len then text = text + char(n1)
        if i+2 < len then text = text + char(n2)
        if i+3 < len then text = text + char(n3)
    end for
    return text
end function

minicrypt.Encode.B32toB26 = function(bi32)
    bi26 = [0] * ceil(bi32.len/26*32)
    low = 0
    high = 26
    j = 0
    for i in range(0, bi26.len-1)
        high = low - 6
        if high < 0 then high = high + 32
        if low < high then
            bi26[i] = floor((bi32[j] % minicrypt.Encode.POW2[high]) / minicrypt.Encode.POW2[low])
        else
            bi26[i] = floor(bi32[j] / minicrypt.Encode.POW2[low])
            if j != bi32.len-1 then
                bi26[i] = bi26[i] + (bi32[j+1] % minicrypt.Encode.POW2[high]) * minicrypt.Encode.POW2[32-low]
                j = j + 1
            end if
        end if
        low = high
    end for
    return bi26
end function

minicrypt.Encode.B26toB32 = function(bi26)
    bi32 = [0] * floor(bi26.len * 26 / 32) // The usage of floor() assumes that the original number had radix 2^32 and therefore the 26-bit representation is generally not used to capacity
    low = 0
    j = 0
    for i in range(0, bi32.len-1)
        high = (low + 6) % 26
        bi32[i] = floor(bi26[j] / minicrypt.Encode.POW2[low])
        if low < 20 then
            if j != bi26.len-1 then
                j = j + 1
                bi32[i] = bi32[i] + (bi26[j] % minicrypt.Encode.POW2[high]) * minicrypt.Encode.POW2[26-low]
            end if
        else
            if j != bi26.len-1 then
                j = j + 1
                bi32[i] = bi32[i] + bi26[j] * minicrypt.Encode.POW2[26-low]
            end if
            if j != bi26.len-1 then
                j = j + 1
                bi32[i] = bi32[i] + (bi26[j] % minicrypt.Encode.POW2[high]) * minicrypt.Encode.POW2[32-high]
            end if
        end if
        low = high
    end for
    return bi32
end function

// Takes a list of 32-bit numbers and returns a Base64 string
// len is the original UTF-16 string length (each char = 2 bytes)
minicrypt.Encode.toBase64 = function(input, len)
    if input.len == 0 then return ""
    I2B64 = minicrypt.Encode.INT2B64
    bytes = []
    for w in input
        val = w
        if val < 0 then val = val + 4294967296
        bytes.push(val % 256)
        bytes.push(floor(val / 256) % 256)
        bytes.push(floor(val / 65536) % 256)
        bytes.push(floor(val / 16777216) % 256)
    end for
    if len then bytes = bytes[:len]
    b64 = ""
    for i in range(0, bytes.len - 1, 3)
        if i >= bytes.len then break
        b0 = bytes[i]
        b1 = 0
        b2 = 0
        if i + 1 < bytes.len then b1 = bytes[i+1]
        if i + 2 < bytes.len then b2 = bytes[i+2]
        v = b0 * 65536 + b1 * 256 + b2
        c0 = floor(v / 262144) % 64
        c1 = floor(v / 4096) % 64
        c2 = floor(v / 64) % 64
        c3 = v % 64
        b64 = b64 + I2B64[c0] + I2B64[c1]
        if i + 1 < bytes.len then
            b64 = b64 + I2B64[c2]
        else
            b64 = b64 + "="
        end if
        if i + 2 < bytes.len then
            b64 = b64 + I2B64[c3]
        else
            b64 = b64 + "="
        end if
    end for
    return b64
end function

// Decodes Base64 into a list of 32-bit numbers
minicrypt.Encode.fromBase64 = function(b64)
    if b64 == null or typeof(b64) != "string" then return null
    if b64.len % 4 != 0 then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_length")
    if b64.len == 0 then return ["", 0]

    I2B64 = minicrypt.Encode.INT2B64
    bytes = []
    for i in range(0, b64.len - 1, 4)
        if i >= b64.len then break
        c0 = b64[i]
        c1 = b64[i+1]
        c2 = b64[i+2]
        c3 = b64[i+3]
        v0 = I2B64.indexOf(c0)
        v1 = I2B64.indexOf(c1)
        if v0 == null or v1 == null then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_char")
        v2 = 0
        v3 = 0
        padCt = 0
        if c2 == "=" then
            padCt = padCt + 1
        else
            v2 = I2B64.indexOf(c2)
            if v2 == null then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_char")
        end if
        if c3 == "=" then
            padCt = padCt + 1
        else
            v3 = I2B64.indexOf(c3)
            if v3 == null then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_char")
        end if
        if c2 == "=" and c3 != "=" then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_padding")
        val = v0 * 262144 + v1 * 4096 + v2 * 64 + v3
        bytes.push(floor(val / 65536) % 256)
        if padCt < 2 then bytes.push(floor(val / 256) % 256)
        if padCt == 0 then bytes.push(val % 256)
    end for
    out = []
    for i in range(0, bytes.len - 1, 4)
        if i >= bytes.len then break
        b0 = bytes[i]
        b1 = 0
        b2 = 0
        b3 = 0
        if i + 1 < bytes.len then b1 = bytes[i+1]
        if i + 2 < bytes.len then b2 = bytes[i+2]
        if i + 3 < bytes.len then b3 = bytes[i+3]
        w = b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
        out.push(w)
    end for
    return [out, bytes.len]
end function

minicrypt.Encode.hexToB32 = function(h)
    if typeof(h) != "string" then return null
    if h.len >= 2 and h[:2] == "0x" then h = h[2:]
    if h == "" then return [0]
    output = []
    HEX2INT = minicrypt.Encode.HEX2INT
    for i in range(0, h.len - 1, 8)
        x = HEX2INT[h[i]]
        for j in range(1, 7)
            if i + j >= h.len then break
            x = x + HEX2INT[ h[i+j] ] * minicrypt.Encode.POW2[j*4]
        end for
        output.push(x)
    end for
    return output
end function

minicrypt.Encode.byteToHex = function(b)
    return minicrypt.Encode.INT2HEX[floor(b/16)] + minicrypt.Encode.INT2HEX[b % 16]
end function

minicrypt.Encode.byteToChar = function(b)
    blacklist = range(0,31) + range(127, 159) + [173]
    if blacklist.indexOf(b) != null then return "."
    return char(b)
end function

minicrypt.Encode.intToHex = function(n)
    h = ""
    for i in range(0, 7)
        h = minicrypt.Encode.INT2HEX[n%16] + h
        n = floor(n / 16)
    end for
    return h
end function

end function //-------------

if not minicrypt.hasIndex("Utils") then __scope()
globals.remove("__scope")