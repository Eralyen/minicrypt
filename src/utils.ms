if not globals.hasIndex("minicrypt") then minicrypt = {}

__scope = function //-------------

minicrypt.Utils = {}

// Turns a base64 string into a hexdump
// @param {string} b64 - a base64 string
// @returns {string | null | error} - returns null if 'b64' isn't a string, an error object if the string isn't a valid base64 string, or the hexdump if 'b64' is a valid base64 string
//
// @example Utils.hexdump("CGRP3BOFU+7MPeny/qLfOL2l73AdkjTzBzgpXlkAbwB1ACAAYwBhAG4AIABsAG8AbwBrACAAYgB1AHQAIAB5AGEAIABjAGEAbgAnAHQAIAB0AG8AdQBjAGgAAAAAAAAAAAAAAAAAAAAAAAAAKuxmZRS64jm2RFJIm5oGUi9SHu2nzMu1NoHZZtv5KYU0QrUdAAAAAAAAAAAAAAAAPgAAAAAAAAAkAAAAAAAAAA==")
// @example 00000000  08 64 4f dc 13 85 53 ee  cc 3d e9 f2 fe a2 df 38  |.dOÜ..SîÌ=éòþ¢ß8|
// @example 00000010  bd a5 ef 70 1d 92 34 f3  07 38 29 5e 59 00 6f 00  |½¥ïp..4ó.8)^Y.o.|
// @example 00000020  75 00 20 00 63 00 61 00  6e 00 20 00 6c 00 6f 00  |u. .c.a.n. .l.o.|
// @example 00000030  6f 00 6b 00 20 00 62 00  75 00 74 00 20 00 79 00  |o.k. .b.u.t. .y.|
// @example 00000040  61 00 20 00 63 00 61 00  6e 00 27 00 74 00 20 00  |a. .c.a.n.'.t. .|
// @example 00000050  74 00 6f 00 75 00 63 00  68 00 00 00 00 00 00 00  |t.o.u.c.h.......|
// @example 00000060  00 00 00 00 00 00 00 00  00 00 00 00 2a ec 66 65  |............*ìfe|
// @example 00000070  14 ba e2 39 b6 44 52 48  9b 9a 06 52 2f 52 1e ed  |.ºâ9¶DRH...R/R.í|
// @example 00000080  a7 cc cb b5 36 81 d9 66  db f9 29 85 34 42 b5 1d  |§ÌËµ6.ÙfÛù).4Bµ.|
// @example 00000090  00 00 00 00 00 00 00 00  00 00 00 00 3e 00 00 00  |............>...|
// @example 000000a0  00 00 00 00 24 00 00 00  00 00 00 00              |....$.......|
minicrypt.Utils.hexdump = function(b64, encoding="base64")
    byteToChar = function(b)
        blacklist = range(0,31) + range(127, 159) + [173]
        if blacklist.indexOf(b) != null then return "."
        return char(b)
    end function

    res = minicrypt.Encode.getEncoding(encoding)
    if typeof(res) == "error" then return res
    encode = res[0]

    val = encode(b64)
    if val == null then return null
    if typeof(val) == "error" then return val
    num = val[0]
    len_bytes = val[1]
    if len_bytes == 0 then return ""
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
        line = minicrypt.Encode.intToHexBE(i) + "  "
        block = bytes[i:i+16]
        for b in block
            line = line + minicrypt.Encode.BYTE2HEX[b] + " "
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