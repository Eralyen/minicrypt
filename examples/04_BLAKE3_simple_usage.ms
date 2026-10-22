// Demonstration of the various BLAKE3 modes of operation
// See https://github.com/Eralyen/minicrypt/wiki/BLAKE3 for more info
import_code("../minicrypt.ms")
b3 = minicrypt.BLAKE3

print b3.hash("Hello World!")
// fea378804f891d95baa796f5316cf55fd6824dce46ab21c30920ea9c1386a516

key = "277d53f8add89cd521dc7be9dc895e250eb1ccb8676977dd5457e8da16432b53"
print b3.keyedHash(key, "Hello World!")
// 0f40f4db3a1baa1b22972273b1263cb7224572b0c3a1f6ef5b3141bdbe4dd409

print b3.deriveKey(key, "example-04 file encryption key")
// 80923dfe77bb038f5b187531d37a8c29ab0c9ebc6834f260a487ef38f9b426ab

// the Hasher and KeyedHasher objects are useful for hashing multiple data sets, especially if the total data is too big to fit in a single string
// Note that the result is the same as b3.hash("Hello World!")
hasher = b3.getHasher
hasher.update("Hello ")
hasher.update("World")
hasher.update("!")
print hasher.finalize
// fea378804f891d95baa796f5316cf55fd6824dce46ab21c30920ea9c1386a516