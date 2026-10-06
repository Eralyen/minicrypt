import_code("../minicrypt.ms")
c20p = minicrypt.ChaCha20Poly1305
encode = minicrypt.Encode
utils = minicrypt.Utils
error = minicrypt.Error

toBytes = function(b64)
    if typeof(b64) != "string" then return null
    if b64.len % 4 != 0 then return minicrypt.Error("minicrypt.Encode.fromBase64", "invalid_length")
    if b64.len == 0 then return [[], 0]
    if ceil((b64.len / 8) * 6) > 16777216 then return minicrypt.Error("minicrypt.Encode.fromBase64", "max_len_exceeded")

    I2B64 = encode.INT2B64
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
    return bytes
end function

fromBytes = function(bytes)
    I2B64 = encode.INT2B64
    b64 = ""
    if bytes.len == 0 then return ""
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

highlightDifferences = function(txt, original)
    highlights = ""
    if txt.len == 0 then return ""
    for i in range(0, txt.len-1)
        c = txt[i]
        if txt[i] != original[i] then c = "<color=red>" + c + "</color>"
        highlights = highlights + c
    end for
    return highlights
end function

while true
    s = ""
    plaintext = "Hello World!"
    aad = "Additional Authenticated Data"
    key = "277d53f8add89cd521dc7be9dc895e250eb1ccb8676977dd5457e8da16432b53"
    msg = null
    encryption_time = null
    verification = null
    extracted_aad = null
    decrypted = null
    decryption_time = null
    reset = false

    while not reset
        s = "====== ChaCha20-Poly1305 Interactive Demo ======" + char(10) +
            "At any point, press [Q] to quit or [R] to reset" + char(10) +
            char(10) +
            "[1] Plaintext:  " + plaintext + char(10) +
            "[2] AAD:        " + aad + char(10) +
            "[3] Secret key: " + key + char(10) +
            "[4] Encrypt! (using the secret key)" + char(10) 
        print(s, true)
        u = user_input("> ", 0, 1)
        if u.upper == "Q" then exit
        if u.upper == "R" then reset = true
        u = u.to_int
        if u == 1 then plaintext = user_input("Plaintext> ")
        if u == 2 then aad = user_input("AAD> ")
        if u == 3 then key = user_input("Secret key (hex, 64 characters)> ")
        if u == 4 then
            start = time
            msg = c20p.encrypt(key, aad, plaintext, "8bit")
            encryption_time = time - start
            if typeof(msg) == "error" then
                print "<color=red>" + msg.code
                wait(1)
            else
                break
            end if
        end if
    end while
    if reset then continue
    prev_s = s

    original_msg = msg
    msg_bytes = toBytes(msg)
    while not reset
        msg = fromBytes(msg_bytes)
        s = prev_s + char(10) +
            "Encrypted message (" + str(encryption_time)[:5] + "s):" + char(10) +
            highlightDifferences(msg, original_msg) + char(10) +
            char(10) +
            highlightDifferences(utils.hexdump(msg), utils.hexdump(original_msg)) + char(10) +
            char(10) +
            "[1] Intercept and edit the message!" + char(10) +
            "[2] Let it through" + char(10)
        print(s, true)

        u = user_input("> ", 0, 1)
        if u.upper == "Q" then exit
        if u.upper == "R" then reset = true
        u = u.to_int
        if u == 1 then 
            byte = user_input("Byte position (hex)> ")
            byte_int = encode.hexToB32(byte)
            if typeof(byte_int) == "error" then
                print "<color=red>" + byte_int.code
                wait(1)
                continue
            end if
            byte_int = byte_int[0]
            if not msg_bytes.hasIndex(byte_int) then
                print "<color=red>out_of_bounds"
                wait(1)
                continue
            end if
            value = user_input("Byte value (hex, 2 characters)> ")
            if not encode.HEX2BYTE.hasIndex(value) then
                print "<color=red>invalid_hex_byte"
                wait(1)
                continue
            end if
            value_int = encode.HEX2BYTE[value]
            msg_bytes[byte_int] = value_int
        end if
        if u == 2 then break
    end while
    if reset then continue
    prev_s = s

    while not reset
        ver_str = ""
        aad_str = ""
        if verification == true  then ver_str = ": <color=green>Success!"
        if verification == false then ver_str = ": <color=red>Fail!"
        if extracted_aad then aad_str = ": " + extracted_aad

        s = prev_s + char(10) +
            "[1] Verify ciphertext integrity (using the secret key)" + ver_str + char(10) +
            "[2] Extract AAD (doesn't require a key)" + aad_str + char(10) +
            "[3] Decrypt! (using the secret key)" + char(10)
        print(s, true)
        
        u = user_input("> ", 0, 1)
        if u.upper == "Q" then exit
        if u.upper == "R" then reset = true
        u = u.to_int
        if u == 1 then verification = c20p.verify(key, msg)
        if u == 2 then
            extracted_aad = c20p.getAad(msg, "8bit") 
            if typeof(extracted_aad) == "error" then
                print "<color=red>" + extracted_aad.code
                extracted_aad = null
                wait(1)
            end if
        end if
        if u == 3 then
            start = time
            decrypted = c20p.decrypt(key, msg, true, "8bit")
            decryption_time = time - start
            if typeof(decrypted) == "error" then 
                print "<color=red>" + decrypted.code
                wait(1)
            else
                decrypted = decrypted[1]
                break
            end if
        end if
    end while
    if reset then continue

    print "Decrypted message (" + str(decryption_time)[:5] + "s):"
    print decrypted
    break
end while