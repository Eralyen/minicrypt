globals.isGH = true
import_code("./MiniTest/MiniTest.src")
import_code("../src/encode.ms")

test_encode = function
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

    expectEqual(minicrypt.Encode.encodeText8(""), [[], 0])
    expectEqual(minicrypt.Encode.encodeText8("abcde"), [[1684234849, 101], 5])
    expectEqual(minicrypt.Encode.decodeText8([1684234849, 101], 5), "abcde")
    expectEqual(minicrypt.Encode.encodeText16(""), [[], 0])
    expectEqual(minicrypt.Encode.encodeText16("abc"), [[6422625, 99], 6])
    expectEqual(minicrypt.Encode.decodeText16([6422625, 99], 6), "abc")
    expectEqual(typeof(minicrypt.Encode.decodeText8([0], 0)), "error")
    expectEqual(typeof(minicrypt.Encode.decodeText16([], 1)), "error")
    expectEqual(typeof(minicrypt.Encode.decodeText16([55296], 2)), "error")

    E = minicrypt.Encode

    expectEqual(E.encodeText15(""), [[], 0])
    expectEqual(E.decodeText15([], 0), "")

    expectEqual(E.decodeText15([0], 4), char(1) * 3)
    expectEqual(E.encodeText15(char(1) * 3), [[0], 4])
    expectEqual(E.decodeText15([4294967295], 4), char(32768) + char(32768) + char(4))
    expectEqual(E.encodeText15(char(32768) + char(32768) + char(4)), [[4294967295], 4])

    expectEqual(E.decodeText15([0], 2), char(1) * 2)
    expectEqual(E.encodeText15(char(1) * 2), [[0], 2])
    expectEqual(E.decodeText15([65535], 2), char(32768) + char(2))
    expectEqual(E.encodeText15(char(32768) + char(2)), [[65535], 2])

    expected = char(25186) + char(18631) + char(406) + char(1)
    expectEqual(E.decodeText15([1684234849, 101], 6), expected)
    expectEqual(E.encodeText15(expected), [[1684234849, 101], 6])

    limbs = [4294967295, 0, 123456789, 1, 4294967295, 7, 305419896, 4294967295]
    for len in range(2, 32, 2)
        input = limbs[:ceil(len / 4)]
        if len % 4 == 2 then input[-1] = input[-1] % 65536
        s = E.decodeText15(input, len)
        expectEqual(s.len, ceil(len * 8 / 15))
        expectEqual(E.encodeText15(s), [input, len])
    end for

    for len in range(2, 32, 2)
        s = E.decodeText15(limbs[:ceil(len / 4)], len)
        for c in s
            expectEqual(code(c) >= 1 and code(c) <= 32768, 1)
        end for
    end for

    expectEqual(typeof(E.decodeText15([], 2)), "error")
    expectEqual(typeof(E.decodeText15([0], 8)), "error")
    expectEqual(typeof(E.decodeText15([0, 0], 4)), "error")

    expectEqual(typeof(E.encodeText15(char(1))), "error")
    expectEqual(typeof(E.encodeText15(char(1) * 17)), "error")
    expectEqual(typeof(E.encodeText15(char(0) + char(1))), "error")
    expectEqual(typeof(E.encodeText15(char(50000) + char(1))), "error")
    expectEqual(typeof(E.encodeText15(char(32769) + char(1))), "error")
    expectEqual(typeof(E.encodeText15(char(1) + char(3))), "error")

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

    expectEqual(minicrypt.Encode.encodeHex("0x0123456789abcdef")[0], [1732584193, 4023233417])
    expectEqual(minicrypt.Encode.encodeHex("")[0], [])
    expectEqual(typeof(minicrypt.Encode.encodeHex("a")), "error")
    expectEqual(typeof(minicrypt.Encode.encodeHex(12)), "error")
    expectEqual(typeof(minicrypt.Encode.encodeHex("01xz")), "error")
    expectEqual(minicrypt.Encode.decodeHex([0, 1, 4294967295]), "0000000001000000ffffffff")
    expectEqual(minicrypt.Encode.B32ToHexBE([0, 1, 4294967295]), ["00000000", "00000001", "ffffffff"])
    expectEqual(minicrypt.Encode.hexBytesToB32("00:01:02:03:04"), [50462976, 4])
end function
TEST "ENCODE", @test_encode

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if