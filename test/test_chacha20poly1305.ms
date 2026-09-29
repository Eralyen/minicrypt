globals.isGH = true
import_code("./MiniTest.src")
import_code("../src/chacha20-poly1305.ms")
import_code("../src/encode.ms")

H2B = {"00":0,"01":1,"02":2,"03":3,"04":4,"05":5,"06":6,"07":7,"08":8,"09":9,"0a":10,"0b":11,"0c":12,"0d":13,"0e":14,"0f":15,"10":16,"11":17,"12":18,"13":19,"14":20,"15":21,"16":22,"17":23,"18":24,"19":25,"1a":26,"1b":27,"1c":28,"1d":29,"1e":30,"1f":31,"20":32,"21":33,"22":34,"23":35,"24":36,"25":37,"26":38,"27":39,"28":40,"29":41,"2a":42,"2b":43,"2c":44,"2d":45,"2e":46,"2f":47,"30":48,"31":49,"32":50,"33":51,"34":52,"35":53,"36":54,"37":55,"38":56,"39":57,"3a":58,"3b":59,"3c":60,"3d":61,"3e":62,"3f":63,"40":64,"41":65,"42":66,"43":67,"44":68,"45":69,"46":70,"47":71,"48":72,"49":73,"4a":74,"4b":75,"4c":76,"4d":77,"4e":78,"4f":79,"50":80,"51":81,"52":82,"53":83,"54":84,"55":85,"56":86,"57":87,"58":88,"59":89,"5a":90,"5b":91,"5c":92,"5d":93,"5e":94,"5f":95,"60":96,"61":97,"62":98,"63":99,"64":100,"65":101,"66":102,"67":103,"68":104,"69":105,"6a":106,"6b":107,"6c":108,"6d":109,"6e":110,"6f":111,"70":112,"71":113,"72":114,"73":115,"74":116,"75":117,"76":118,"77":119,"78":120,"79":121,"7a":122,"7b":123,"7c":124,"7d":125,"7e":126,"7f":127,"80":128,"81":129,"82":130,"83":131,"84":132,"85":133,"86":134,"87":135,"88":136,"89":137,"8a":138,"8b":139,"8c":140,"8d":141,"8e":142,"8f":143,"90":144,"91":145,"92":146,"93":147,"94":148,"95":149,"96":150,"97":151,"98":152,"99":153,"9a":154,"9b":155,"9c":156,"9d":157,"9e":158,"9f":159,"a0":160,"a1":161,"a2":162,"a3":163,"a4":164,"a5":165,"a6":166,"a7":167,"a8":168,"a9":169,"aa":170,"ab":171,"ac":172,"ad":173,"ae":174,"af":175,"b0":176,"b1":177,"b2":178,"b3":179,"b4":180,"b5":181,"b6":182,"b7":183,"b8":184,"b9":185,"ba":186,"bb":187,"bc":188,"bd":189,"be":190,"bf":191,"c0":192,"c1":193,"c2":194,"c3":195,"c4":196,"c5":197,"c6":198,"c7":199,"c8":200,"c9":201,"ca":202,"cb":203,"cc":204,"cd":205,"ce":206,"cf":207,"d0":208,"d1":209,"d2":210,"d3":211,"d4":212,"d5":213,"d6":214,"d7":215,"d8":216,"d9":217,"da":218,"db":219,"dc":220,"dd":221,"de":222,"df":223,"e0":224,"e1":225,"e2":226,"e3":227,"e4":228,"e5":229,"e6":230,"e7":231,"e8":232,"e9":233,"ea":234,"eb":235,"ec":236,"ed":237,"ee":238,"ef":239,"f0":240,"f1":241,"f2":242,"f3":243,"f4":244,"f5":245,"f6":246,"f7":247,"f8":248,"f9":249,"fa":250,"fb":251,"fc":252,"fd":253,"fe":254,"ff":255}
B2H = ["00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"]

min = function(a, b)
    if a <= b then return a
    return b
end function

// Deserialization from test vector format to lists of 32-bit numbers
// Input format: 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
deserialize = function(txt)
    output = []
    T = txt.split(":")
    for i in range(0, T.len-1, 4)
        output.push(0)
        for j in range(min(i+3, T.len-1), i)
            output[-1] = output[-1] * 256 + H2B[T[j]]
        end for
    end for
    return output
end function

// n = 32 bits
int2Hex = function(n)
    return B2H[floor(n/16777216)%256] + B2H[floor(n/65536)%256] + B2H[floor(n/256)%256] + B2H[n%256]
end function

// state = 16 numbers, 32-bit
state2Hex = function(state)
    output = []
    for s in state
        output.push(int2Hex(s))
    end for
    return output
end function

// https://www.rfc-editor.org/info/rfc8439/#section-2.3.2
TEST "ChaCha.chachaBlock", function
    key = deserialize("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
    nonce = deserialize("00:00:00:09:00:00:00:4a:00:00:00:00")
    counter = 1
    output = [0] * 16
    minicrypt.ChaCha.ROUNDS = 20
    state = [1634760805,  857760878, 2036477234, 1797285236] + 
            key + 
            [counter] +
            nonce
    expected_state = ["61707865", "3320646e", "79622d32", "6b206574",
                      "03020100", "07060504", "0b0a0908", "0f0e0d0c",
                      "13121110", "17161514", "1b1a1918", "1f1e1d1c",
                      "00000001", "09000000", "4a000000", "00000000"]
    expectEqual(state2Hex(state), expected_state, "State initialization")

    expected_final = ["e4e7f110", "15593bd1", "1fdd0f50", "c47120a3",
                      "c7f4d1c7", "0368c033", "9aaa2204", "4e6cd4c3",
                      "466482d2", "09aa9f07", "05d7c214", "a2028bd9",
                      "d19c12b5", "b94e16de", "e883d0cb", "4e3c50a2"]
    minicrypt.ChaCha.chachaBlock(output, state)
    expectEqual(state2Hex(output), expected_final, "State after 20 ChaChaBlock rounds + addition")
end function

// https://www.rfc-editor.org/info/rfc8439/#section-2.4.2
TEST "ChaCha.encrypt - ChaCha.decrypt", function
    // problem: the test case uses 8-bit characters while GH uses 16-bit characters.
    // convert 'the plaintext' to 8-bit characters just this time
    serializeTextUTF16UTF8 = function(text)
        output = []
        if text.len == 0 then return output
        for i in range(0, text.len - 1, 4)
            c = code(text[i])
            if i + 1 < text.len then c = code(text[i+1]) * 256 + c
            if i + 2 < text.len then c = code(text[i+2]) * 65536 + c
            if i + 3 < text.len then c = code(text[i+3]) * 16777216 + c
            //if i + 4 >= text.len then c = c * 256^(text.len % 4)
            output.push(c)
        end for
        return output
    end function
    minicrypt.ChaCha.ROUNDS = 20
    key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".replace(":", "")
    nonce = "00:00:00:00:00:00:00:4a:00:00:00:00".replace(":", "")
    counter = 1
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext, "UTF-8", "base64", nonce, counter)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext, "UTF-8")
    ciphertext_len = minicrypt.Encode.fromBase64(ciphertext)[1]
    expectEqual(ciphertext_len-20, plaintext.len, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext, "Successive encryption and decryption 1")

    plaintext = plaintext[:-1]
    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext)
    expectEqual(minicrypt.Encode.fromBase64(ciphertext)[1]-20, plaintext.len*2, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext, "Successive encryption and decryption 2")
    
    plaintext = plaintext[:-1]    
    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext)
    expectEqual(minicrypt.Encode.fromBase64(ciphertext)[1]-20, plaintext.len*2, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext, "Successive encryption and decryption 3")
    
    plaintext = plaintext[:-1]    
    ciphertext = minicrypt.ChaCha.encrypt(key, plaintext)
    deciphered = minicrypt.ChaCha.decrypt(key, ciphertext)
    expectEqual(minicrypt.Encode.fromBase64(ciphertext)[1]-20, plaintext.len*2, "Base64 ciphertext length")
    expectEqual(deciphered, plaintext, "Successive encryption and decryption 4")
end function

TEST "ChaCha.keygen", function
    key = deserialize("80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f")
    nonce = deserialize("00:00:00:00:00:01:02:03:04:05:06:07")
    expected = deserialize("8a:d5:a0:8b:90:5f:81:cc:81:50:40:27:4a:b2:94:71:a8:33:b6:37:e3:fd:0d:a5:08:db:b8:e2:fd:d1:a6:46")
    expectEqual(minicrypt.ChaCha.keygen(key, nonce), expected)
end function

TEST "Poly1305.macRaw", function
    key = deserialize("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b")
    msg = minicrypt.Encode.encodeText8("Cryptographic Forum Research Group")[0]
    tag = deserialize("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")
    expectEqual(minicrypt.Poly1305.macRaw(key, msg, 34), tag)
end function

TEST "ChaCha20Poly1305.*Raw", function
    key = deserialize("80:81:82:83:84:85:86:87:88:89:8a:8b:8c:8d:8e:8f:90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f")
    aad = deserialize("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7")
    aad_len = 12
    nonce = deserialize("07:00:00:00:40:41:42:43:44:45:46:47")
    counter = 1
    plaintext = minicrypt.Encode.encodeText8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")[0]
    plaintext_len = 114
    res = minicrypt.ChaCha20Poly1305.encryptRaw(key, nonce, aad, aad_len, plaintext, plaintext_len)
    aead = res[0]
    mac = res[1]
    aead_expected = deserialize("50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7:00:00:00:00:d3:1a:8d:34:64:8e:60:db:7b:86:af:bc:53:ef:7e:c2:a4:ad:ed:51:29:6e:08:fe:a9:e2:b5:a7:36:ee:62:d6:3d:be:a4:5e:8c:a9:67:12:82:fa:fb:69:da:92:72:8b:1a:71:de:0a:9e:06:0b:29:05:d6:a5:b6:7e:cd:3b:36:92:dd:bd:7f:2d:77:8b:8c:98:03:ae:e3:28:09:1b:58:fa:b3:24:e4:fa:d6:75:94:55:85:80:8b:48:31:d7:bc:3f:f4:de:f0:8e:4b:7a:9d:e5:76:d2:65:86:ce:c6:4b:61:16:00:00:00:00:00:00:00:00:00:00:00:00:00:00:0c:00:00:00:00:00:00:00:72:00:00:00:00:00:00:00")
    
    expectEqual(aead, aead_expected, "AEAD")
    expectTrue(minicrypt.ChaCha20Poly1305.verifyRaw(key, mac, nonce, aead), "Verification of authentic AEAD")

    aead_tampered = aead[:]
    aead_tampered[2] = aead_tampered[2] + 1
    expectFalse(minicrypt.ChaCha20Poly1305.verifyRaw(key, mac, nonce, aead_tampered), "Rejection of tampered AEAD")

    res = minicrypt.ChaCha20Poly1305.decryptRaw(key, nonce, aead)
    deciphered = res[2]
    expectEqual(deciphered, plaintext, "Deciphered text matches")
end function

TEST "Malformed AEAD", function
    key = "171a007b5321e458b8f74a802f71bbfa6c35a9443159191d9b7ba3944908367c"
    aad = "Visible text"
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    ciphertext_b64 = minicrypt.ChaCha20Poly1305.encrypt(key, aad, plaintext)
    ciphertext = minicrypt.Encode.fromBase64(ciphertext_b64)[0]

    res = minicrypt.ChaCha20Poly1305.splitMessage(ciphertext)
    tag = res[0]
    nonce = res[1]
    aead = res[2]
    
    res = minicrypt.ChaCha20Poly1305.splitAEAD(aead)
    aad = res[0]
    aad_len = res[1]
    ciphertext = res[2]
    ciphertext_len = res[3]

    msg1 = minicrypt.Encode.toBase64(tag + nonce)
    msg2 = minicrypt.Encode.toBase64(tag + nonce + [4294967296, 4294967296, 4294967296, 4294967296])
    msg3 = minicrypt.Encode.toBase64(tag + nonce + aead + [0, 0, 0, 0])
    msg4 = minicrypt.Encode.toBase64(tag + nonce + aead[:-1])

    // add tag or nonce manipulation
    msg5 = ""
    msg6 = "h€h€"
    msg7 = ciphertext_b64[1:]
    msg8 = ciphertext_b64[:-1]
    msg9 = ciphertext_b64 + "==="
    msg10 = "=" + ciphertext_b64

    tampered_nonce = nonce[:]
    tampered_nonce[0] = tampered_nonce[0] + 1
    msg11 = minicrypt.Encode.toBase64(tag + tampered_nonce + aead)
    msg12 = minicrypt.Encode.toBase64(tag + [0,0,0] + aead)

    // These are checking that the program doesn't crash mostly
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg1))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg2))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg3))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg4))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg5))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg6))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg7))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg8))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg9))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg10))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg11))
    expectNull(minicrypt.ChaCha20Poly1305.decrypt(key, msg12))

    // There are supposed to not crash and also to return false instead of null when something fails
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg1))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg2))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg3))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg4))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg5))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg6))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg7))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg8))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg9))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg10))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg11))
    expectFalse(minicrypt.ChaCha20Poly1305.verify(key, msg12))
end function

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if