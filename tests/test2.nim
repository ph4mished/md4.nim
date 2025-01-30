import std/[sysrand, unittest]

import md4

const inputsize = 2000
const maxwrite = 300
# check buffer handling for various write sizes
let buffer = urandom(inputsize)
var ctx = NewMD4()
ctx.Update(buffer)
let expected = ctx.Final()
for writesize in 1..maxwrite:
    ctx = NewMD4()
    var firstbyte = 0
    while firstbyte < inputsize:
        let lastbyte = min(firstbyte + writesize, inputsize) - 1
        ctx.Update(buffer[firstbyte..lastbyte])
        firstbyte = lastbyte + 1
    let got = ctx.Final()
    check(expected == got)
