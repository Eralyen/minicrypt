import_code("../minicrypt.ms")
c20p = minicrypt.ChaCha20Poly1305

key = "277d53f8add89cd521dc7be9dc895e250eb1ccb8676977dd5457e8da16432b53"

file = get_shell.host_computer.File("/root/my_file.txt")
if file == null then exit("<color=red>Before running this program, create /root/my_file.txt and write something in it.")
content = file.get_content

// this does not get encrypted, but it does get protected by the message authentication code
additional_authenticated_data = "Encryption date: " + current_date 

encrypted = c20p.encrypt(key, content, additional_authenticated_data)
file.set_content(encrypted)

user_input("If you like, open the file and mess with the encrypted text (optional), then press [Return] ")

encrypted = file.get_content

if c20p.verify(key, encrypted) then
    decrypted = c20p.decrypt(key, encrypted)
    plaintext = decrypted[0]
    aad = decrypted[1]
    print "AAD: " + aad
    file.set_content(plaintext)
else
    exit("<color=red>ERROR: the key is incorrect or the file has been modified.")
end if