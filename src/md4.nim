# Copyright © 2025 Mark Glines
# License: MIT

## This is a pure Nim implementation of MD4.
## It's mostly useful for compatibility with older MD4-based stuff, like ed2ksum.
##
## The output is an array of 16 bytes.
## It operates on blocks of 64 bytes, buffering partial blocks as needed.
##
## Disclaimers:
## * MD4 is kinda old, and is NOT considered a secure cryptographic hash nowadays.
## * The unpredictability of its output should not be relied upon for security purposes.
## * This library makes no attempt to protect your data against side-channel attacks, or anything else, really.

runnableExamples:
    var ctx = newMD4()
    ctx.update("message digest")
    let result = ctx.final()

    import std/[sequtils, strutils]
    let hexstr = map(result, proc(x: byte): string = toHex(x)).join
    assert toLowerAscii(hexstr) == "d9130a8164549fe818874806e1c7014b"


import std/sequtils

const bufsize = 64

# MD4 context.
type MD4_CTX = tuple
    state: array[4, uint32] # state (ABCD)
    buffer: array[64, byte] # input buffer
    buffered_bytes: int
    processed_blocks: int

proc newMD4*(): MD4_CTX =
    ## Initialize a new MD4 context.
    result.state = [
        0x67452301'u32,
        0xefcdab89'u32,
        0x98badcfe'u32,
        0x10325476'u32,
    ]
    return result

# helper functions
proc pack_le32(output: var array[16, uint32], input: array[64, uint8]) {.inline.} =
    for i in 0..15:
        output[i] = (uint32(input[i*4+0]) shl 0) or
                    (uint32(input[i*4+1]) shl 8) or
                    (uint32(input[i*4+2]) shl 16) or
                    (uint32(input[i*4+3]) shl 24)

func unpack_le32(output: var openArray[uint8], input: openArray[uint32]) {.inline.} =
    assert len(output) == 4*len(input)
    for i in 0..len(input)-1:
        output[i*4+0] = uint8((input[i] shr 0) and 0xff)
        output[i*4+1] = uint8((input[i] shr 8) and 0xff)
        output[i*4+2] = uint8((input[i] shr 16) and 0xff)
        output[i*4+3] = uint8((input[i] shr 24) and 0xff)

# constants for process
const SHIFT: array[12, uint8] = [3, 7, 11, 19, 3, 5, 9, 13, 3, 9, 11, 15]

# step ops for process
func rol(a: var uint32, i: uint8) {.inline.} =
    assert i < 33
    a = (a shl i) or (a shr (32-i))

func F(x, y, z: uint32): uint32 {.inline.} =
    result = (x and y) or ((not x) and z)
func G(x, y, z: uint32): uint32 {.inline.} =
    result = (x and y) or (x and z) or (y and z)
func H(x, y, z: uint32): uint32 {.inline.} =
    result = x xor y xor z

proc FF(a: var uint32, b, c, d, x: uint32, s: uint8) {.inline.} =
    a += F(b, c, d) + x
    rol(a, s)
proc GG(a: var uint32, b, c, d, x: uint32, s: uint8) {.inline.} =
    a += G(b, c, d) + x + 0x5a827999'u32
    rol(a, s)
proc HH(a: var uint32, b, c, d, x: uint32, s: uint8) {.inline.} =
    a += H(b, c, d) + x + 0x6ed9eba1'u32
    rol(a, s)

proc process_block(ctx: var MD4_CTX) =
    # echo "process_block called"
    ctx.processed_blocks += 1
    ctx.buffered_bytes = 0

    var a = ctx.state[0]
    var b = ctx.state[1]
    var c = ctx.state[2]
    var d = ctx.state[3]
    var x: array[16, uint32]
    pack_le32(x, ctx.buffer)

    # round 1
    for i in 0..3:
        let i4 = i*4
        FF(a, b, c, d, x[i4+0], SHIFT[0])
        FF(d, a, b, c, x[i4+1], SHIFT[1])
        FF(c, d, a, b, x[i4+2], SHIFT[2])
        FF(b, c, d, a, x[i4+3], SHIFT[3])

    # round 2
    for i in 0..3:
        GG(a, b, c, d, x[i+0], SHIFT[4])
        GG(d, a, b, c, x[i+4], SHIFT[5])
        GG(c, d, a, b, x[i+8], SHIFT[6])
        GG(b, c, d, a, x[i+12], SHIFT[7])

    # round 3
    for i in 0..3:
        let il = [0, 2, 1, 3][i]
        HH(a, b, c, d, x[il+0], SHIFT[8])
        HH(d, a, b, c, x[il+8], SHIFT[9])
        HH(c, d, a, b, x[il+4], SHIFT[10])
        HH(b, c, d, a, x[il+12], SHIFT[11])

    ctx.state[0] += a
    ctx.state[1] += b
    ctx.state[2] += c
    ctx.state[3] += d

proc update*(ctx: var MD4_CTX, data: openArray[byte]) =
    ## Hash some raw data.
    var inputlen = len(data)
    var inputoff = 0
    var startindex = ctx.buffered_bytes
    var remainsize = bufsize - startindex
    var copysize = min(inputlen, remainsize)
    var endindex = startindex + copysize - 1

    ctx.buffer[startindex..endindex] = data[0..copysize-1]
    ctx.buffered_bytes += copysize
    inputoff += copysize
    inputlen -= copysize

    while ctx.buffered_bytes == bufsize:
        # process whole block
        process_block(ctx)

        # buffer is now empty; refill it
        copysize = min(inputlen, bufsize)
        if copysize == 0:
            break
        endindex = copysize - 1

        ctx.buffer[0..endindex] = data[inputoff..inputoff+endindex]
        ctx.buffered_bytes = copysize
        inputoff += copysize
        inputlen -= copysize

proc update*(ctx: var MD4_CTX, data: seq[byte]) {.inline.} =
    ## Hash some raw data.
    ctx.update(data.toOpenArray(0, len(data)-1))

proc update*(ctx: var MD4_CTX, data: openArray[char]) {.inline.} =
    ## Hash some raw data.
    ctx.update(data.toOpenArrayByte(0, len(data)-1))

proc update*(ctx: var MD4_CTX, data: seq[char]) {.inline.} =
    ## Hash some raw data.
    ctx.update(data.toOpenArrayByte(0, len(data)-1))

proc update*(ctx: var MD4_CTX, data: string) {.inline.} =
    ## Interptet a string as bytes and hash it.
    ctx.update(data.toOpenArrayByte(0, len(data)-1))

proc final*(ctx: var MD4_CTX): array[16, byte] =
    ## Generate the final output.  Only call this once.
    let bitcount = (ctx.buffered_bytes + (ctx.processed_blocks * bufsize)) shl 3

    # add padding, to flush through any buffered data
    let padding = if ctx.buffered_bytes < 56:
        55 - ctx.buffered_bytes
    else:
        119 - ctx.buffered_bytes
    ctx.update(@[0x80'u8])
    ctx.update(repeat(0x0'u8, padding))

    # add bit counts
    var counts: array[2, uint32]
    # echo fmt"bitcount is {bitcount:#x}"
    counts[0] = uint32(bitcount and 0xffffffff)
    counts[1] = uint32(bitcount shr 32)
    var countbytes: seq[byte] = @[0, 0, 0, 0, 0, 0, 0, 0]
    unpack_le32(countbytes, counts)
    ctx.update(countbytes)

    unpack_le32(result, ctx.state)
