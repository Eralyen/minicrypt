_test_main = true
import_code("test_bigint.ms")
import_code("test_encode.ms")
import_code("test_utils.ms")
import_code("test_chacha20poly1305_rfc8439.ms")
import_code("test_chacha20poly1305.ms")

RUN_ALL_TESTS
print "<color=green>Done!"
print "Runtime: " + str(time)[:4] + "s"