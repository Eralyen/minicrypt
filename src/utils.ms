if not globals.hasIndex("minicrypt") then minicrypt = {}

__scope = function //-------------

minicrypt.Utils = {}
minicrypt.Utils.hexdump = function(b64)
    byteToChar = function(b)
        blacklist = range(0,31) + range(127, 159) + [173]
        if blacklist.indexOf(b) != null then return "."
        return char(b)
    end function

    val = minicrypt.Encode.fromBase64(b64)
    if val == null then return null
    num = val[0]
    len_bytes = val[1]
    bytes = []
    for i in range(0, num.len-1)
        bytes.push(num[i] % 256)
        num[i] = floor(num[i] / 256)
        if i*4 + 1 < len_bytes then
            bytes.push(num[i] % 256)
            num[i] = floor(num[i] / 256)
        end if
        if i*4 + 2 < len_bytes then
            bytes.push(num[i] % 256)
            num[i] = floor(num[i] / 256)
        end if
        if i*4 + 3 < len_bytes then
            bytes.push(num[i] % 256)
            num[i] = floor(num[i] / 256)
        end if
    end for

    hexdump = []
    for i in range(0, bytes.len-1, 16)
        line = minicrypt.Encode.intToHex(i) + "  "
        block = bytes[i:i+16]
        for b in block
            line = line + minicrypt.Encode.byteToHex(b) + " "
        end for
        line = line + "   " * (16 - block.len)
        line = line[:34] + " " + line[34:] + " |"
        for b in block
            line = line + byteToChar(b)
        end for
        line = line + "|"
        hexdump.push(line)
    end for
    return hexdump.join(char(10))
end function

end function //-------------

if not minicrypt.hasIndex("Utils") then __scope()
globals.remove("__scope")