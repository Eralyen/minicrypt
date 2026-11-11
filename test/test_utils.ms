globals.isGH = true
import_code("./MiniTest/MiniTest.src")
import_code("../src/encode.ms")
import_code("../src/utils.ms")

test_hexdump = function
    expectEqual(minicrypt.Utils.hexdump(""), "")

    short_dump = minicrypt.Utils.hexdump(minicrypt.Encode.toBase64([67305985], 4))
    expected = "00000000  01 02 03 04 " + "   " * 12
    expected = expected[:34] + " " + expected[34:] + " |....|"
    expectEqual(short_dump, expected)
    
    bytes = minicrypt.Encode.encodeText8("abcdefghijklmnopq")[1]
    b64 = minicrypt.Encode.toBase64(bytes, 17)
    lines = minicrypt.Utils.hexdump(b64).split(char(10))

    expectEqual(lines.len, 2)
    expectEqual(lines[0], "00000000  61 62 63 64 65 66 67 68  69 6a 6b 6c 6d 6e 6f 70  |abcdefghijklmnop|")

    expected_last = "00000010  71 " + "   " * 15
    expected_last = expected_last[:34] + " " + expected_last[34:] + " |q|"
    expectEqual(lines[1], expected_last)

    expectEqual(typeof(minicrypt.Utils.hexdump("!!!!")), "error")
end function
TEST "UTILS - Hexdump", @test_hexdump

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if