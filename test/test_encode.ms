globals.isGH = true
import_code("./MiniTest/MiniTest.src")
import_code("../src/encode.ms")

test_encode_b32to_b26 = function
    bi32 = [4078784323, 3787266857, 1866653276, 3980223449]
    bi26 = [52252483, 54971004, 31837723, 56999179, 15547747]
    res = minicrypt.Encode.B32toB26(bi32)
    expectEqual(res, bi26)

    bi32 = [4078784323, 3787266857, 1866653276, 3980223449, 2188448744, 3794152570, 3970912016, 2025583602, 2741976039, 2456772636, 3444865498, 888482765, 1087261713, 3444653798, 1280254342, 3072359811, 2668078665, 1096835929, 685689349, 2130529749, 1829688326, 1942337814, 988146106, 1165560999, 3657534284, 2302706558, 3452594094, 723000822, 51471233, 2704941066, 3906206717, 3991179606, 1281944996, 1088721742, 3783357791, 3851833447, 1191161536, 1256017377, 2947295481, 3495119398, 2905043554, 2968244184, 1750625517, 1705690631, 3406069800, 397451706, 3170188596, 319149437, 3885421532, 1550618015, 673801488, 2478531674, 1163329293, 1990375181, 2699523328, 22770060, 36327]
    bi26 = [52252483, 54971004, 31837723, 56999179, 15547747, 10241274, 40028072, 20726664, 66251951, 31338236, 37155774, 29196402, 7985810, 49509205, 18042706, 16988464, 22101734, 63463859, 64500932, 19324033, 27199398, 5773526, 32284756, 20403363, 425725, 26952629, 54287249, 60270313, 17606458, 47386974, 65904664, 35979789, 30042030, 34045363, 37229233, 2624581, 27343392, 37027583, 38344046, 62297015, 55463016, 63977764, 35133269, 39403935, 61784293, 58216895, 60075476, 46051491, 5458470, 31234228, 16616146, 62309295, 57170028, 23769473, 4719238, 42396460, 20191152, 57621839, 19946839, 39538544, 9281511, 21239579, 27427478, 38727057, 22478605, 11387729, 55576426, 36864925, 50420593, 9081, 0]
    res = minicrypt.Encode.B32toB26(bi32)
    expectEqual(res, bi26)
end function
TEST "ENCODE - Encode.B32toB26", @test_encode_b32to_b26

test_encode_b26to_b32 = function
    bi32 = [4294967295] // 2^32-1
    bi26 = [67108863, 63]
    res = minicrypt.Encode.B26toB32(bi26)
    expectEqual(res, bi32)
    
    bi32 = [4078784323, 3787266857, 1866653276, 3980223449]
    bi26 = [52252483, 54971004, 31837723, 56999179, 15547747]
    res = minicrypt.Encode.B26toB32(bi26)
    expectEqual(res, bi32)

    bi32 = [4078784323, 3787266857, 1866653276, 3980223449, 2188448744, 3794152570, 3970912016, 2025583602, 2741976039, 2456772636, 3444865498, 888482765, 1087261713, 3444653798, 1280254342, 3072359811, 2668078665, 1096835929, 685689349, 2130529749, 1829688326, 1942337814, 988146106, 1165560999, 3657534284, 2302706558, 3452594094, 723000822, 51471233, 2704941066, 3906206717, 3991179606, 1281944996, 1088721742, 3783357791, 3851833447, 1191161536, 1256017377, 2947295481, 3495119398, 2905043554, 2968244184, 1750625517, 1705690631, 3406069800, 397451706, 3170188596, 319149437, 3885421532, 1550618015, 673801488, 2478531674, 1163329293, 1990375181, 2699523328, 22770060, 36327]
    bi26 = [52252483, 54971004, 31837723, 56999179, 15547747, 10241274, 40028072, 20726664, 66251951, 31338236, 37155774, 29196402, 7985810, 49509205, 18042706, 16988464, 22101734, 63463859, 64500932, 19324033, 27199398, 5773526, 32284756, 20403363, 425725, 26952629, 54287249, 60270313, 17606458, 47386974, 65904664, 35979789, 30042030, 34045363, 37229233, 2624581, 27343392, 37027583, 38344046, 62297015, 55463016, 63977764, 35133269, 39403935, 61784293, 58216895, 60075476, 46051491, 5458470, 31234228, 16616146, 62309295, 57170028, 23769473, 4719238, 42396460, 20191152, 57621839, 19946839, 39538544, 9281511, 21239579, 27427478, 38727057, 22478605, 11387729, 55576426, 36864925, 50420593, 9081, 0]
    res = minicrypt.Encode.B26toB32(bi26)
    expectEqual(res, bi32)
end function
TEST "ENCODE - Encode.B26toB32", @test_encode_b26to_b32

test_encode_to_base64 = function
    toB64 = function(s)
        return minicrypt.Encode.toBase64(minicrypt.Encode.encodeText16(s)[0], s.len*2)
    end function
    expectEqual(toB64(""), "")
    expectEqual(toB64("f"), "ZgA=")
    expectEqual(toB64("fo"), "ZgBvAA==")
    expectEqual(toB64("foo"), "ZgBvAG8A")
    expectEqual(toB64("foob"), "ZgBvAG8AYgA=")
    expectEqual(toB64("fooba"), "ZgBvAG8AYgBhAA==")
    expectEqual(toB64("foobar"), "ZgBvAG8AYgBhAHIA")
end function
TEST "ENCODE - Encode.toBase64", @test_encode_to_base64

test_encode_from_base64 = function
    fromB64 = function(s)
        decoded = minicrypt.Encode.fromBase64(s)
        return minicrypt.Encode.decodeText16(decoded[0], decoded[1])
    end function
    expectEqual(fromB64(""), "")
    expectEqual(fromB64("ZgA="), "f")
    expectEqual(fromB64("ZgBvAA=="), "fo")
    expectEqual(fromB64("ZgBvAG8A"), "foo")
    expectEqual(fromB64("ZgBvAG8AYgA="), "foob")
    expectEqual(fromB64("ZgBvAG8AYgBhAA=="), "fooba")
    expectEqual(fromB64("ZgBvAG8AYgBhAHIA"), "foobar")
    expectEqual(minicrypt.Encode.fromBase64(minicrypt.Encode.toBase64([4078784323, 3787266857, 1866653276, 3980223449, 2188448744, 3794152570, 3970912016, 2025583602, 2741976039, 2456772636, 3444865498, 888482765, 1087261713, 3444653798, 1280254342, 3072359811, 2668078665, 1096835929, 685689349, 2130529749, 1829688326, 1942337814, 988146106, 1165560999, 3657534284, 2302706558, 3452594094, 723000822, 51471233, 2704941066, 3906206717, 3991179606, 1281944996, 1088721742, 3783357791, 3851833447, 1191161536, 1256017377, 2947295481, 3495119398, 2905043554, 2968244184, 1750625517, 1705690631, 3406069800, 397451706, 3170188596, 319149437, 3885421532, 1550618015, 673801488, 2478531674, 1163329293, 1990375181, 2699523328, 22770060, 36327], 114*2))[0],
                                                  [4078784323, 3787266857, 1866653276, 3980223449, 2188448744, 3794152570, 3970912016, 2025583602, 2741976039, 2456772636, 3444865498, 888482765, 1087261713, 3444653798, 1280254342, 3072359811, 2668078665, 1096835929, 685689349, 2130529749, 1829688326, 1942337814, 988146106, 1165560999, 3657534284, 2302706558, 3452594094, 723000822, 51471233, 2704941066, 3906206717, 3991179606, 1281944996, 1088721742, 3783357791, 3851833447, 1191161536, 1256017377, 2947295481, 3495119398, 2905043554, 2968244184, 1750625517, 1705690631, 3406069800, 397451706, 3170188596, 319149437, 3885421532, 1550618015, 673801488, 2478531674, 1163329293, 1990375181, 2699523328, 22770060, 36327])
end function
TEST "ENCODE - Encode.fromBase64", @test_encode_from_base64

test_encode_text_boundaries = function
    expectEqual(minicrypt.Encode.encodeText8(""), [[], 0])
    expectEqual(minicrypt.Encode.encodeText8("abcde"), [[1684234849, 101], 5])
    expectEqual(minicrypt.Encode.decodeText8([1684234849, 101], 5), "abcde")
    expectEqual(minicrypt.Encode.encodeText16(""), [[], 0])
    expectEqual(minicrypt.Encode.encodeText16("abc"), [[6422625, 99], 6])
    expectEqual(minicrypt.Encode.decodeText16([6422625, 99], 6), "abc")
    expectEqual(typeof(minicrypt.Encode.decodeText8([0], 0)), "error")
    expectEqual(typeof(minicrypt.Encode.decodeText16([], 1)), "error")
    expectEqual(typeof(minicrypt.Encode.decodeText16([55296], 2)), "error")
end function
TEST "ENCODE - Text encoding boundaries", @test_encode_text_boundaries

test_encode_text15_boundaries = function
    E = minicrypt.Encode
    PAD = char(32769)

    // --- empty ---
    expectEqual(E.encodeText15(""), [[], 0])
    expectEqual(E.decodeText15([], 0), "")

    // --- single limb, no padding ---
    // 32 bits -> 3 chars (15 + 15 + 2 bits), each stored as value+1
    expectEqual(E.decodeText15([0], 4), char(1) + char(1) + char(1))
    expectEqual(E.encodeText15(char(1) + char(1) + char(1)), [[0], 4])
    expectEqual(E.decodeText15([1], 4), char(2) + char(1) + char(1))
    expectEqual(E.encodeText15(char(2) + char(1) + char(1)), [[1], 4])

    // all 32 bits set: 32767, 32767, 3 -> char(32768), char(32768), char(4)
    expectEqual(E.decodeText15([4294967295], 4), char(32768) + char(32768) + char(4))
    expectEqual(E.encodeText15(char(32768) + char(32768) + char(4)), [[4294967295], 4])

    // --- padding: 1 to 3 pad chars when len is not a multiple of 4 ---
    // 1 byte -> 3 chars + 3 pad
    expectEqual(E.decodeText15([0], 1), char(1) * 3 + PAD * 3)
    expectEqual(E.encodeText15(char(1) * 3 + PAD * 3), [[0], 1])
    // 2 bytes -> 2 pad
    expectEqual(E.decodeText15([0], 2), char(1) * 3 + PAD * 2)
    expectEqual(E.encodeText15(char(1) * 3 + PAD * 2), [[0], 2])
    // 3 bytes -> 1 pad
    expectEqual(E.decodeText15([0], 3), char(1) * 3 + PAD)
    expectEqual(E.encodeText15(char(1) * 3 + PAD), [[0], 3])

    // 5 bytes vs 8 bytes: same limb count, must be distinguishable
    expectEqual(E.encodeText15(char(1) * 5 + PAD * 3), [[0, 0], 5])
    expectEqual(E.encodeText15(char(1) * 5), [[0, 0], 8])

    // --- value spanning two limbs ("abcde" as in the text8 test) ---
    // limb 1 = 25185 + 18630*2^15 + 1*2^30, limb 2 contributes 101 << 2 to the third char
    expected = char(25186) + char(18631) + char(406) + char(1) + char(1) + PAD * 3
    expectEqual(E.decodeText15([1684234849, 101], 5), expected)
    expectEqual(E.encodeText15(expected), [[1684234849, 101], 5])

    // --- round trips for every pad amount ---
    limbs = [4294967295, 0, 123456789, 1]
    for len in range(13, 16)
        input = limbs[:ceil(len / 4)]
        expectEqual(E.encodeText15(E.decodeText15(input, len)), [input, len])
    end for

    // --- every produced character is in the safe range ---
    s = E.decodeText15([4294967295, 4294967295, 0, 305419896], 16)
    for c in s
        expectEqual(code(c) >= 1 and code(c) <= 32769, 1)
    end for

    // --- decode errors ---
    expectEqual(typeof(E.decodeText15([], 1)), "error")           // length mismatch
    expectEqual(typeof(E.decodeText15([0], 8)), "error")          // length mismatch
    expectEqual(typeof(E.decodeText15([0, 0], 4)), "error")       // length mismatch
    expectEqual(typeof(E.decodeText15([0], 16777217)), "error")   // > 2^24

    // --- encode errors ---
    expectEqual(typeof(E.encodeText15(char(0))), "error")                       // below range
    expectEqual(typeof(E.encodeText15(char(50000))), "error")                   // above range
    expectEqual(typeof(E.encodeText15(char(1) + PAD + char(1))), "error")       // pad char mid-string
    expectEqual(typeof(E.encodeText15(char(1) * 3 + PAD * 4)), "error")         // more than 3 pad chars
    expectEqual(typeof(E.encodeText15(PAD)), "error")
end function
TEST "ENCODE - Text15 encoding boundaries", @test_encode_text15_boundaries

test_encode_base64_boundaries = function
    expectEqual(minicrypt.Encode.toBase64([67305985], 0), "")
    expectEqual(minicrypt.Encode.toBase64([67305985]), "AQIDBA==")
    expectEqual(minicrypt.Encode.fromBase64("AQ=="), [[1], 1])
    expectEqual(minicrypt.Encode.fromBase64("AQI="), [[513], 2])
    expectEqual(minicrypt.Encode.fromBase64("AQID"), [[197121], 3])
    expectEqual(minicrypt.Encode.fromBase64("AQIDBA=="), [[67305985], 4])
    expectEqual(minicrypt.Encode.fromBase64(""), [[], 0])

    expectEqual(typeof(minicrypt.Encode.fromBase64("Zg==AAAA")), "error")
    expectEqual(typeof(minicrypt.Encode.fromBase64("Zm=8")), "error")
    expectEqual(typeof(minicrypt.Encode.fromBase64("AB==")), "error")
    expectEqual(typeof(minicrypt.Encode.fromBase64("AAB=")), "error")
    expectEqual(typeof(minicrypt.Encode.fromBase64("abc")), "error")
    expectEqual(typeof(minicrypt.Encode.fromBase64("!!!!")), "error")
    expectEqual(typeof(minicrypt.Encode.fromBase64(123)), "error")
end function
TEST "ENCODE - Base64 padding and explicit lengths", @test_encode_base64_boundaries

test_encode_hex_boundaries = function
    expectEqual(minicrypt.Encode.hexToB32("0x0123456789abcdef"), [1732584193, 4023233417])
    expectEqual(minicrypt.Encode.hexToB32("a"), [160])
    expectEqual(minicrypt.Encode.hexToB32(""), [0])
    expectEqual(typeof(minicrypt.Encode.hexToB32(12)), "error")
    expectEqual(typeof(minicrypt.Encode.hexToB32("01xz")), "error")
    expectEqual(minicrypt.Encode.B32ToHex([0, 1, 4294967295]), ["00000000", "00000001", "ffffffff"])
    expectEqual(minicrypt.Encode.hexBytesToB32("00:01:02:03:04"), [50462976, 4])
end function
TEST "ENCODE - Hex conversion boundaries", @test_encode_hex_boundaries

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if