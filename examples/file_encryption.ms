import_code("../minicrypt.ms")
c20p = minicrypt.ChaCha20Poly1305

key = "277d53f8add89cd521dc7be9dc895e250eb1ccb8676977dd5457e8da16432b53"

//file = get_shell.host_computer.File("/root/your_file.txt")
content = "File contents etc etc" //file.get_content

// this does not get encrypted, but it does get protected by the message authentication code
additional_authenticated_data = "Encryption date: " + current_date 

encrypted = c20p.encrypt(key, additional_authenticated_data, content)

// encrypted is a base64 string, something like:
// AfySikaXfRDNsn+FZFEi4/WAGoTPgCJ8iZbNdEUAbgBjAHIA
// eQBwAHQAaQBvAG4AIABkAGEAdABlADoAIAAzAC8ATwBjAHQA
// LwAyADAAMgA2ACAALQAgADEAMQA6ADQAOAAAAAAAAAAAAAAA
// By3DMBuZtCCIIEH4qJ7eFpvPfn5cDjOvgx5oAMyfpEXO3H/Q
// Lm/4buAkAAAAAAAARgAAAAAAAAAqAAAAAAAAAA==

//file.set_content(encrypted)

// some time later...

//encrypted = file.get_content

if c20p.verify(key, encrypted) then
    decrypted = c20p.decrypt(key, encrypted)
    aad = decrypted[0]
    plaintext = decrypted[1]

    //file.set_content(plaintext)
else
    exit("Warning: the key is incorrect or the file has been tampered with")
end if