import std/[sequtils, strutils, unittest]

include md4

# check initial state
var ctx = NewMD4()
assert ctx.state == [
    0x67452301'u32,
    0xefcdab89'u32,
    0x98badcfe'u32,
    0x10325476'u32,
]
assert ctx.buffered_bytes == 0
assert ctx.processed_blocks == 0

# check ctx.Update()'s buffer handling
for i in 0..14:
  assert ctx.buffered_bytes == i * 4
  ctx.Update(@[byte(i*4+1), byte(i*4+2), byte(i*4+3), byte(i*4+4)])
  assert ctx.buffered_bytes == (i+1) * 4
ctx.Update(@[byte(61), byte(62), byte(63)])
assert ctx.buffered_bytes == 63
assert ctx.processed_blocks == 0
ctx.Update(@[byte(64)])
assert ctx.buffered_bytes == 0
assert ctx.processed_blocks == 1
for i in 0..63:
  assert ctx.buffer[i] == byte(i+1)

# test cases from RFC 1320 section A.5
let testcases: seq[tuple[input: string, hexoutput: string]] = @[
      ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
      ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
      ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
      ("message digest", "d9130a8164549fe818874806e1c7014b"),
      ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
      ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
      ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"),
]

for testcase in testcases:
  # echo fmt"starting new test case: input is {testcase.input}, length is {len(testcase.input)}, hexoutput is {testcase.hexoutput}"
  var ctx = NewMD4()
  # copy input string into byte seq
  var inputbytes = newSeq[byte](0)
  insert(inputbytes, toOpenArrayByte(testcase.input, 0, len(testcase.input)-1), 0)
  ctx.Update(inputbytes)
  let result_array = ctx.Final()
  let result_hexstr = map(result_array, proc(x: byte): string = toLowerAscii(toHex(x))).join

  check(testcase.hexoutput == result_hexstr)
