// See https://github.com/Eralyen/minicrypt/wiki/ChaCha20%E2%80%90Poly1305 for more info

import_code("../minicrypt.ms")
c20p = minicrypt.ChaCha20Poly1305

key = "277d53f8add89cd521dc7be9dc895e250eb1ccb8676977dd5457e8da16432b53"
encrypted_message = c20p.encrypt(key, "My secret message", "Additional Authenticated Data (this does not get encrypted)")

print encrypted_message
// 1dgJhj10tr/YOIgB5g+aK3QgrO2AU7E5ICOVHkEAZABkAGkAdABpAG8AbgBhAGwAIABBAHUAdABoAGUAbgB0AGkAYwBhAHQAZQBkACAARABhAHQAYQAgACgAdABoAGkAcwAgAGQAbwBlAHMAIABuAG8AdAAgAGcAZQB0ACAAZQBuAGMAcgB5AHAAdABlAGQAKQAAAAAAAAAAAAAA5BpOSjE2zhMnYmg5lqHSvokX2TS7coU1xBisx50eowR3mgAAAAAAAAAAAAAAAAAAdgAAAAAAAAAiAAAAAAAAAA==

decrypted = c20p.decrypt(key, encrypted_message)

print decrypted
// ["My secret message", "Additional Authenticated Data (this does not get encrypted)"]