import std/[sequtils, strutils, unittest]

include md4

# `char` and `byte` are both uint8, but `byte` is a direct alias; `char` is more cooked.
# make sure all input types generate the same hash output.

var outputs: seq[array[16, byte]]

let inputstr = "abc\xff"
let inputsc: seq[char] = @['a', 'b', 'c', '\xff']
let inputsb: seq[byte] = @['a'.ord.uint8, 'b'.ord.uint8, 'c'.ord.uint8, 0xff]

# byte openarray
var ctx = NewMD4()
ctx.Update(inputsb.toOpenArray(0, len(inputsb)-1))
outputs.add(ctx.Final())
# char openarray
ctx = NewMD4()
ctx.Update(inputsc.toOpenArray(0, len(inputsc)-1))
outputs.add(ctx.Final())
# byte seq
ctx = NewMD4()
ctx.Update(inputsb)
outputs.add(ctx.Final())
# char seq
ctx = NewMD4()
ctx.Update(inputsc)
outputs.add(ctx.Final())
# string
ctx = NewMD4()
ctx.Update(inputstr)
outputs.add(ctx.Final())

for i in 1..len(outputs)-1:
    check(outputs[0] == outputs[i])
