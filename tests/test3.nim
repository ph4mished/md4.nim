import std/[sequtils, strutils, unittest]

include md4

# `char` and `byte` are both uint8, but `byte` is a direct alias; `char` is more cooked.
# make sure all input types generate the same hash output.

var outputs: seq[array[16, byte]]

let inputstr = "abc\xff"
let inputsc: seq[char] = @['a', 'b', 'c', '\xff']
let inputsb: seq[byte] = @['a'.ord.uint8, 'b'.ord.uint8, 'c'.ord.uint8, 0xff]

# byte openarray
var ctx = newMD4()
ctx.update(inputsb.toOpenArray(0, len(inputsb)-1))
outputs.add(ctx.final())
# char openarray
ctx = newMD4()
ctx.update(inputsc.toOpenArray(0, len(inputsc)-1))
outputs.add(ctx.final())
# byte seq
ctx = newMD4()
ctx.update(inputsb)
outputs.add(ctx.final())
# char seq
ctx = newMD4()
ctx.update(inputsc)
outputs.add(ctx.final())
# string
ctx = newMD4()
ctx.update(inputstr)
outputs.add(ctx.final())

for i in 1..len(outputs)-1:
    check(outputs[0] == outputs[i])
