# HashCryptor-2.0
This is a much safer version of my HashCryptor algorithm, 
which uses a random salt in combination with the password to make it even harder to identify similar file contents when encrypted with the same password.

This is a small file encryption program with a GUI, random salts and it's based on my hash algorithm. It can encrypt all types of files that have only ascii-characters. 
It has three modes of operation: "Encrypt", "Decrypt" and "Edit in ShadowMode". Obfuscation is done by using several chained hashes that are then layed over the file contents in a tree shaped mapping scheme. 
It resaves the file as a .crypt file and consists of the salt and spaced numbers only, looking quite beautiful :). 

Make sure you install the glimmer-dsl-libui gem by running "gem install glimmer-dsl-libui" or "sudo gem install glimmer-dsl-libui" in your terminal window.
If that is done, it is compatible with both Windows and Linux.

The password for the included test.rb.crypt file is just "test".

Enjoy! 
