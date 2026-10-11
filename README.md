# minicrypt
minicrypt is a cryptography library written in [MiniScript](https://miniscript.org/) 1.5.1 that aims to deliver secure, fast, and user-friendly algorithms to Grey Hack players, and hopefully the MiniScript community at large.

## Getting Started
Visit the Wiki, or browse the examples.

To start writing an application, import minicrypt.ms or just the modules you need. The imported modules are contained in `globals.minicrypt`.

Greybel isn't required, but compilation without it is not being tested at this time.

If you have any questions or concerns, feel free to open an issue, or contact me on Discord or email.

## Algorithms
### Symmetric Encryption
- ChaCha: a stream cypher that should be much faster than AES in Greyscript and MiniScript applications.
- ChaCha20-Poly1305: an AEAD algorithm that provides authentication and additional authenticated data in plaintext.

### Authentication
- Poly1305: a one-time keyed authentication algorithm

### Planned
- A hashing function: at least one of:
    - SHA-256
    - BLAKE3
- A cryptographically secure RNG
- A HMAC
- Public-key cryptography: at least one of
    - RSA
    - Curve25519

## Contributing
Feedback, contributions, bug reports and suggestions are very welcome! See `CONTRIBUTING.md` and `SECURITY.md`

## License
Distributed under the MIT license, excluding MiniTest which is licensed under GNU LGPLv3.