import std/[sysrand, unittest]

import md4

const inputsize = 2000
const maxwrite = 300
# check buffer handling for various write sizes
let buffer = urandom(inputsize)
var ctx = newMD4()
ctx.update(buffer)
let expected = ctx.final()
for writesize in 1..maxwrite:
    ctx = newMD4()
    var firstbyte = 0
    while firstbyte < inputsize:
        let lastbyte = min(firstbyte + writesize, inputsize) - 1
        ctx.update(buffer[firstbyte..lastbyte])
        firstbyte = lastbyte + 1
    let got = ctx.final()
    check(expected == got)
