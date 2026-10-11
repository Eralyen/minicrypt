if not globals.hasIndex("minicrypt") then minicrypt = {}

import_code("./error.ms")

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
minicrypt.Encode.HEX2BYTE = {"00":0,"01":1,"02":2,"03":3,"04":4,"05":5,"06":6,"07":7,"08":8,"09":9,"0a":10,"0b":11,"0c":12,"0d":13,"0e":14,"0f":15,"10":16,"11":17,"12":18,"13":19,"14":20,"15":21,"16":22,"17":23,"18":24,"19":25,"1a":26,"1b":27,"1c":28,"1d":29,"1e":30,"1f":31,"20":32,"21":33,"22":34,"23":35,"24":36,"25":37,"26":38,"27":39,"28":40,"29":41,"2a":42,"2b":43,"2c":44,"2d":45,"2e":46,"2f":47,"30":48,"31":49,"32":50,"33":51,"34":52,"35":53,"36":54,"37":55,"38":56,"39":57,"3a":58,"3b":59,"3c":60,"3d":61,"3e":62,"3f":63,"40":64,"41":65,"42":66,"43":67,"44":68,"45":69,"46":70,"47":71,"48":72,"49":73,"4a":74,"4b":75,"4c":76,"4d":77,"4e":78,"4f":79,"50":80,"51":81,"52":82,"53":83,"54":84,"55":85,"56":86,"57":87,"58":88,"59":89,"5a":90,"5b":91,"5c":92,"5d":93,"5e":94,"5f":95,"60":96,"61":97,"62":98,"63":99,"64":100,"65":101,"66":102,"67":103,"68":104,"69":105,"6a":106,"6b":107,"6c":108,"6d":109,"6e":110,"6f":111,"70":112,"71":113,"72":114,"73":115,"74":116,"75":117,"76":118,"77":119,"78":120,"79":121,"7a":122,"7b":123,"7c":124,"7d":125,"7e":126,"7f":127,"80":128,"81":129,"82":130,"83":131,"84":132,"85":133,"86":134,"87":135,"88":136,"89":137,"8a":138,"8b":139,"8c":140,"8d":141,"8e":142,"8f":143,"90":144,"91":145,"92":146,"93":147,"94":148,"95":149,"96":150,"97":151,"98":152,"99":153,"9a":154,"9b":155,"9c":156,"9d":157,"9e":158,"9f":159,"a0":160,"a1":161,"a2":162,"a3":163,"a4":164,"a5":165,"a6":166,"a7":167,"a8":168,"a9":169,"aa":170,"ab":171,"ac":172,"ad":173,"ae":174,"af":175,"b0":176,"b1":177,"b2":178,"b3":179,"b4":180,"b5":181,"b6":182,"b7":183,"b8":184,"b9":185,"ba":186,"bb":187,"bc":188,"bd":189,"be":190,"bf":191,"c0":192,"c1":193,"c2":194,"c3":195,"c4":196,"c5":197,"c6":198,"c7":199,"c8":200,"c9":201,"ca":202,"cb":203,"cc":204,"cd":205,"ce":206,"cf":207,"d0":208,"d1":209,"d2":210,"d3":211,"d4":212,"d5":213,"d6":214,"d7":215,"d8":216,"d9":217,"da":218,"db":219,"dc":220,"dd":221,"de":222,"df":223,"e0":224,"e1":225,"e2":226,"e3":227,"e4":228,"e5":229,"e6":230,"e7":231,"e8":232,"e9":233,"ea":234,"eb":235,"ec":236,"ed":237,"ee":238,"ef":239,"f0":240,"f1":241,"f2":242,"f3":243,"f4":244,"f5":245,"f6":246,"f7":247,"f8":248,"f9":249,"fa":250,"fb":251,"fc":252,"fd":253,"fe":254,"ff":255}
minicrypt.Encode.BYTE2HEX = ["00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"]

minicrypt.Encode.POW2 = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888, 1099511627776, 2199023255552, 4398046511104, 8796093022208, 17592186044416, 35184372088832, 70368744177664, 140737488355328, 281474976710656, 562949953421312, 1125899906842624, 2251799813685248, 4503599627370496]


// Takes a string and returns a list of 32-bit numbers. 16 bits per character, the default Grey Hack string encoding. Returns [output, byte_len]
// @param {string} text - any string
// @returns {list}      - [output, byte_len] -> [list<number>, number]
minicrypt.Encode.encodeText16 = function(text)
    output = []
    if text.len == 0 then return [output, 0]
    if text.len > 8388608 then return minicrypt.Error("minicrypt.Encode.encodeText16", "max_len_exceeded") // 8388608 = 2^24 / 2 (because 2 bytes per character)
    for i in range(0, text.len - 1, 2)
        c1 = code(text[i])
        c2 = 0
        if i + 1 < text.len then c2 = code(text[i+1])
        output.push(c2 * 65536 + c1)
    end for
    return [output, text.len*2]
end function

// Takes a string and returns a list of 32-bit numbers. 8 bits per character. Returns [output, byte_len]
// @param {string} text - any string
// @returns {list}      - [output, byte_len] -> [list<number>, number]
minicrypt.Encode.encodeText8 = function(text)
    output = []
    if text.len == 0 then return [output, 0]
    if text.len > 16777216 then return minicrypt.Error("minicrypt.Encode.decodeText16", "max_len_exceeded") // 16777216 = 2^24 (because 1 byte per character)
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

// Takes a list of 32-bit numbers and returns a string. 16 bits per character, the default Grey Hack string encoding. If any one character would throw a runtime error (char codes between 55296 and 57343) it returns an error.
// @param {list<number>} input - a list of 32-bit integers
// @param {number}       len   - the length of the input in bytes. Max 2^24
// @returns {string}           - the decoded string
minicrypt.Encode.decodeText16 = function(input, len)
    text = ""
    if input.len != ceil(len/4) then return minicrypt.Error("minicrypt.Encode.decodeText16", "length_mismatch")
    if len > 16777216 then return minicrypt.Error("minicrypt.Encode.decodeText16", "max_len_exceeded") // 16777216 = 2^24
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

// Takes a list of 32-bit numbers and returns a string. 8 bits per character.
// @param {list<number>} input - a list of 32-bit integers
// @param {number}       len   - the length of the input in bytes. Max 2^24
// @returns {string}           - the decoded string
minicrypt.Encode.decodeText8 = function(input, len)
    text = ""
    if input.len != ceil(len/4) then return minicrypt.Error("minicrypt.Encode.decodeText8", "length_mismatch")
    if len > 16777216 then return minicrypt.Error("minicrypt.Encode.decodeText8", "max_len_exceeded") // 16777216 = 2^24
    if input.len == 0 then return ""
    for i in range(0, input.len-1)
        n = input[i]
        for j in range(0, 3)
            if i*4 + j >= len then break
            text = text + char(n % 256)
            n = floor(n / 256)
        end for
    end for
    return text
end function

// Turns a big integer from base 2^32 to base 2^26, which enables big integer math
// @param {list<number>} bi32   - a list of 32-bit integers
// @returns {list<number>}      - a list of 26-bit integers
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

// Turns a big integer from base 2^26 to base 2^32
// @param {list<number>} bi26   - a list of 26-bit integers
// @returns {list<number>}      - a list of 32-bit integers
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

// Takes a list of 32-bit numbers and returns a base64 string
// @param {list<number>} input - a list of 32-bit integers
// @param {number}       len   - the length of 'input' in bytes. Max 2^24
// @returns {string}           - the base64 representation of the input 
minicrypt.Encode.toBase64 = function(input, len)
    if input.len == 0 then return ""
    if len > 16777216 then return minicrypt.Error("minicrypt.Encode.toBase64", "max_len_exceeded") // 16777216 = 2^24
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
    if len != null then bytes = bytes[:len]
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

// Decodes base64 into a list of 32-bit numbers and its length in bytes. Returns [output, byte_len] if the string is valid.
// @param {string} b64 - the base64 string
// @returns {list | error | null}     - Returns [output, byte_len] -> [list<number>, number] if 'b64' is valid. Returns null if 'b64' is not a string, or an error object if it's not a valid base64 string (invalid character or invalid padding)
minicrypt.Encode.fromBase64 = function(b64)
    if typeof(b64) != "string" then return null
    if b64.len % 4 != 0 then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_length")
    if b64.len == 0 then return [[], 0]
    if ceil((b64.len / 8) * 6) > 16777216 then return minicrypt.Error("minicrypt.Encode.fromBase64", "max_len_exceeded")

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
        if padCt > 0 and i + 4 < b64.len then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_padding")
        if c2 == "=" and v1 % 16 != 0 then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_padding")
        if c3 == "=" and c2 != "=" and v2 % 4 != 0 then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_padding")
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

// Turns a hex string into a list of 32-bit integers.
// @param {string}                        h - the hex string
// @returns {list<number> | null | error}   - returns null if h is not a string, error if it's not a valid hex string, or the encoded list of 32-bit integers otherwise.
minicrypt.Encode.hexToB32 = function(h)
    if typeof(h) != "string" then return null
    if h.len >= 2 and h[:2] == "0x" then h = h[2:]
    if h == "" then return [0]
    output = []
    HEX2INT = minicrypt.Encode.HEX2INT
    for i in range(0, h.len - 1, 8)
        x = 0
        for j in range(0, 7, 2)
            if i + j >= h.len then break
            if not HEX2INT.hasIndex(h[i+j]) then return minicrypt.Error("minicrypt.Encode.hexToB32", "invalid_char")
            byte = HEX2INT[h[i+j]] * 16
            if i + j + 1 < h.len then
                if not HEX2INT.hasIndex(h[i+j+1]) then return minicrypt.Error("minicrypt.Encode.hexToB32", "invalid_char")
                byte = byte + HEX2INT[h[i+j+1]]
            end if
            x = x + byte * minicrypt.Encode.POW2[j*4]
        end for
        output.push(x)
    end for
    return output
end function

// Turns a list of 32-bit integers into a hex string
// @param {list<number>} input - a list of 32-bit integers
// @returns {string}           - the hex string
minicrypt.Encode.B32ToHex = function(input)
    output = []
    for x in input
        output.push(minicrypt.Encode.intToHex(x))
    end for
    return output
end function

// Turns a 32-bit integer into a hex string
// @param {number}   n - a 32-bit integer
// @returns {string}   - the hex string
minicrypt.Encode.intToHex = function(n)
    h = ""
    for i in range(0, 7)
        h = minicrypt.Encode.INT2HEX[n%16] + h
        n = floor(n / 16)
    end for
    return h
end function

// Deserialization from test vector format to lists of 32-bit numbers
// Input format: 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
// @param {string} text     - the hex bytes
// @returns {list<number>} - a list of 32-bit integers
minicrypt.Encode.hexBytesToB32 = function(text)
    min = function(a, b)
        if a <= b then return a
        return b
    end function
    output = []
    T = text.split(":")
    for i in range(0, T.len-1, 4)
        output.push(0)
        for j in range(min(i+3, T.len-1), i)
            output[-1] = output[-1] * 256 + minicrypt.Encode.HEX2BYTE[T[j]]
        end for
    end for
    return output
end function

end function //-------------

if not minicrypt.hasIndex("Utils") then __scope()
globals.remove("__scope")