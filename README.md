# MD4

This is a pure Nim implementation of MD4.
It's mostly useful for compatibility with older MD4-based stuff, like ed2ksum.

The output is an array of 16 bytes.
It operates on blocks of 64 bytes, buffering partial blocks as needed.

# Disclaimers

* MD4 is kinda old, and is NOT considered a secure cryptographic hash nowadays.
* The unpredictability of its output should not be relied upon for security purposes.
* This library makes no attempt to protect your data against side-channel attacks, or anything else, really.

# Example

```nim
import md4

# hash a string (also accepts seq and openArray)
var ctx = NewMD4()
ctx.Update("message digest")
let result = ctx.Final()

import std/[sequtils, strutils]
let hexstr = map(result, proc(x: byte): string = toHex(x)).join
assert toLowerAscii(hexstr) == "d9130a8164549fe818874806e1c7014b"
```

# License

MIT.  Have fun!
