# Primitive file cryptor
Study project written in 8086 assembly language.

Using modular addition method with a key.

# Installation
Assemble and bulid it using TASM and TLINK
```
tasm crypt
tlink crypt
```

# Usage
Through DOS command line
```
crypt [path] [key]
```
Encrypted files got the same name, but .cry extension. Using this command on .cry file will try to decrypt it with given key.
