# HashCryptor-2.0
This is a much safer version of my HashCryptor algorithm, 
which uses a random initial vector in comination with the password to make it even harder to identify similar file contents when encrypted with the same password.

This is a small file encryption program with a GUI, random inital vectors and it's based on my hash algorithm. It can encrypt all types of files that have only ascii-characters. 
It has three modes of operation: "Encrypt", "Decrypt" and "Edit in ShadowMode". Obfuscation is done by using several chained hashes that are then layed over the file contents in a tree shaped mapping scheme. 
It resaves the file as a .crypt file and consists of the initial vector and spaced numbers only, looking quite beautiful :). Enjoy!