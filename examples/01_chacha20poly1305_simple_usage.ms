import_code("../minicrypt.ms")
c20p = minicrypt.ChaCha20Poly1305
utils = minicrypt.Utils

key = "277d53f8add89cd521dc7be9dc895e250eb1ccb8676977dd5457e8da16432b53"
encrypted_message = c20p.encrypt(key, "Additional Authenticated Data (this does not get encrypted)", "My secret message")

decrypted = c20p.decrypt(key, encrypted_message)

print decrypted
// ["Additional Authenticated Data (this does not get encrypted)", "My secret message"]