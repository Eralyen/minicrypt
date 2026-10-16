# minicrypt
minicrypt is a cryptography library written in [MiniScript](https://miniscript.org/) 1.5.1 that aims to deliver secure, fast, and user-friendly algorithms to Grey Hack players, and hopefully the MiniScript community at large.

## Getting Started
Visit the [Wiki](https://github.com/Eralyen/minicrypt/wiki), or browse the [examples](https://github.com/Eralyen/minicrypt/tree/main/examples).

To start writing an application, import minicrypt.ms or just the modules you need. The imported modules are contained in `globals.minicrypt`.

[greybel-vs](https://github.com/ayecue/greybel-vs) is not required, but compilation without it is not being tested at this time.

If you have any questions or concerns, feel free to open an issue, or contact me on my Discord or email.

## Algorithms

Rather than implementing the classic algorithms such as SHA-2, AES, RSA, we focus on bleeding-edge, proven algorithms with excellent software efficiency.

### Symmetric Encryption
- ChaCha: a stream cypher that should be much faster than AES in Greyscript and MiniScript applications.
- ChaCha20-Poly1305: an AEAD algorithm that provides authentication and additional authenticated data in plaintext.

### Hashing and key derivation:
- BLAKE3: a fast hasing algorithm that supports generic hashing, keyed hashing, and key derivation.

### Authentication
- Poly1305: a one-time keyed authentication algorithm

### Planned
- Public-key cryptography:
    - Ed25519 (signing)
    - X25519 (encryption)
- A cryptographically secure RNG

#### Under consideration
- A PBKDF such as Argon2 or Balloon hashing

## Contributing
Feedback, contributions, bug reports and suggestions are very welcome! See `CONTRIBUTING.md` and `SECURITY.md`

## License
Distributed under the MIT license, excluding MiniTest which is licensed under GNU LGPLv3.
