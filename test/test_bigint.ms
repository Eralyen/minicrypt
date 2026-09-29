globals.isGH = true
import_code("./MiniTest.src")
import_code("../src/bigint.ms")

BigInt = minicrypt.BigInt
BigInt.init

TEST "BigInt.init", function
    expectEqual(BigInt.BITS, BigInt.W * BigInt.N, 
        "BigInt.BITS = BigInt.W * BigInt.N")

    expectEqual(BigInt.MAXVAL1, 2^BigInt.W,
        "BigInt.MAXVAL1 = 2^BigInt.W")

    expectEqual(BigInt.MAXVAL1, BigInt.MAXVAL+1, 
        "BigInt.MAXVAL1 = BigInt.MAXVAL + 1")
end function

TEST "BigInt.Utils.random", function
    expectNotEq(BigInt.Utils.random(0, BigInt.MAXVAL), BigInt.Utils.random(0, BigInt.MAXVAL), 
        "Two random numbers drawn at the same time should not be identical")
end function

TEST "BigInt.times10", function
    ten = BigInt.zero
    ten[0] = 10

    expectEqual(BigInt.times10(BigInt.zero), BigInt.zero, "0 * 10 = 0")
    expectEqual(BigInt.times10(BigInt.one), ten, "1 * 10 = 10")

    long1 = BigInt.zero
    long2 = BigInt.zero
    for i in range(0, BigInt.N-1)
        long1[i] = i
        long2[i] = i * 10
    end for

    expectEqual(BigInt.times10(long1), long2, "Big integer times 10 with no carry")
end function

TEST "BigInt.fromString", function
    ten = BigInt.zero
    ten[0] = 10
    expectEqual(BigInt.fromString("10"), ten, """10"" -> 10")
    expectEqual(BigInt.fromString("0"), BigInt.zero, """0"" -> 0")

    BigInt.init(260, 26)
    dec = "1298918588980553635187775861008647412032396015923828298485241649935894022413625"
    int = [37707065, 53997979, 45245992, 17144902, 50241228, 38808266, 21094974, 494070, 37938067, 47050359]
    expectEqual(BigInt.fromString(dec), int)
    BigInt.init
end function

TEST "BigInt.toString", function
    ten = BigInt.zero
    ten[0] = 10
    expectEqual(BigInt.toString(ten), "10", "10 -> ""10""")
    expectEqual(BigInt.toString(BigInt.zero), "0", "0 -> ""0""")
end function

TEST "BigInt.cmp", function
    n1 = BigInt.one
    n0 = BigInt.zero
    nn1 = BigInt.negOne
    expectEqual(BigInt.cmp(n1, n1), 0, "cmp(1,1) = 0")
    expectEqual(BigInt.cmp(n1, n0), 1, "cmp(1,0) = 1")
    expectEqual(BigInt.cmp(n0, n1), -1, "cmp(0,1) = -1")
    expectEqual(BigInt.cmp(nn1, nn1), 0, "cmp(-1,-1) = 0")
    expectEqual(BigInt.cmp(nn1, n1), -1, "cmp(-1,1) = -1")
    expectEqual(BigInt.cmp(n1, nn1), 1, "cmp(1,-1) = 1")
end function

TEST "BigInt.invertP", function
    three = BigInt.fromSmall(3)
    four = BigInt.fromSmall(4)
    eleven = BigInt.fromSmall(11)
    expectEqual(BigInt.invertP(four, eleven), three, "4^-1 = 3 mod 11")
    n271 = BigInt.fromSmall(271)
    n383 = BigInt.fromSmall(383)
    n106 = BigInt.fromSmall(106)
    expectEqual(BigInt.invertP(n271, n383), n106, "271^-1 = 106 mod 383")
end function

TEST "BigInt.mult", function
    BigInt.init(128, 26)
    a = [45781294, 66360979, 8747345, 63161984, 54681217]
    b = [3260956, 142, 8268, 508120, 568309]
    c = [3849480, 43865974, 7289493, 6596178, 24153398, 17295018, 23827609, 6585633, 62592801, 463065]
    expectEqual(BigInt.mult(a, b, false), c, "No trim")
    expectEqual(BigInt.mult(a, b, true), c[:5], "Trim")
    BigInt.init
end function

TEST "BigInt.specMod", function
    BigInt.init(156, 26)
    x = [3849480, 43865974, 7289493, 6596178, 24153398, 17295018, 23827609, 6585633, 62592801, 463065, 0, 0]
    p = [67108859, 67108863, 67108863, 67108863, 67108863, 0]
    res = [23215706, 28786292, 40217660, 51124727, 26468727, 0]
    expectEqual(BigInt.specMod(x, 5, 5, p), res)
    BigInt.init
end function

if not globals.hasIndex("_test_main") then
    RUN_ALL_TESTS
    print "<color=green>Done!"
    print "Runtime: " + str(time)[:4] + "s"
end if