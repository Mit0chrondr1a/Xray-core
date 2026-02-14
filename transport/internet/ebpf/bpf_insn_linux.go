//go:build linux

package ebpf

// bpfInsn represents a single BPF instruction matching struct bpf_insn.
type bpfInsn struct {
	code uint8
	dst  uint8 // 4 bits
	src  uint8 // 4 bits
	off  int16
	imm  int32
}

// encode encodes a BPF instruction into a uint64 in little-endian format
// matching the kernel's struct bpf_insn layout:
//
//	struct bpf_insn {
//	    __u8 code;           // byte 0
//	    __u8 dst_reg:4;      // byte 1, low nibble
//	    __u8 src_reg:4;      // byte 1, high nibble
//	    __s16 off;           // bytes 2-3
//	    __s32 imm;           // bytes 4-7
//	};
func (i bpfInsn) encode() uint64 {
	return uint64(i.code) |
		uint64(i.dst&0xf)<<8 |
		uint64(i.src&0xf)<<12 |
		uint64(uint16(i.off))<<16 |
		uint64(uint32(i.imm))<<32
}

// encodeBPFInsns encodes a slice of bpfInsn into a slice of uint64.
func encodeBPFInsns(insns []bpfInsn) []uint64 {
	result := make([]uint64, len(insns))
	for i, insn := range insns {
		result[i] = insn.encode()
	}
	return result
}

// BPF instruction classes
const (
	bpfClassLD    = 0x00
	bpfClassLDX   = 0x01
	bpfClassST    = 0x02
	bpfClassSTX   = 0x03
	bpfClassALU   = 0x04
	bpfClassJMP   = 0x05
	bpfClassJMP32 = 0x06
	bpfALU64      = 0x07
)

// BPF ALU/ALU64 operations
const (
	bpfAdd = 0x00
	bpfSub = 0x10
	bpfMul = 0x20
	bpfDiv = 0x30
	bpfOr  = 0x40
	bpfAnd = 0x50
	bpfLSH = 0x60
	bpfRSH = 0x70
	bpfNeg = 0x80
	bpfMod = 0x90
	bpfXor = 0xa0
	bpfMov = 0xb0
	bpfEnd = 0xd0
)

// BPF jump operations
const (
	bpfJA   = 0x00
	bpfJEQ  = 0x10
	bpfJGT  = 0x20
	bpfJGE  = 0x30
	bpfJSET = 0x40
	bpfJNE  = 0x50
	bpfJSGT = 0x60
	bpfJSGE = 0x70
	bpfJLT  = 0xa0
	bpfJLE  = 0xb0
	bpfCall = 0x80
	bpfExit = 0x90
)

// BPF source modifiers
const (
	bpfK = 0x00 // immediate
	bpfX = 0x08 // register
)

// BPF size modifiers
const (
	bpfW  = 0x00 // word (4 bytes)
	bpfH  = 0x08 // half-word (2 bytes)
	bpfB  = 0x10 // byte
	bpfDW = 0x18 // double-word (8 bytes)
)

// BPF memory access modes
const (
	bpfIMM = 0x00
	bpfABS = 0x20
	bpfIND = 0x40
	bpfMEM = 0x60
	bpfATOMIC = 0xc0
)

// BPF endianness
const (
	bpfToLE = 0x00
	bpfToBE = 0x08
)

// BPF helper function IDs
const (
	bpfFuncMapLookupElem    = 1
	bpfFuncMapUpdateElem    = 2
	bpfFuncMapDeleteElem    = 3
	bpfFuncKtimeGetNs       = 5
	bpfFuncXdpAdjustHead    = 44
	bpfFuncGetSocketCookie  = 46
	bpfFuncMsgCorkBytes     = 70
	bpfFuncMsgRedirectHash  = 71
	bpfFuncSKRedirectHash   = 72
)

// BPF pseudo map fd source register value
const bpfPseudoMapFD = 1

// BPF registers
const (
	bpfRegR0  = 0
	bpfRegR1  = 1
	bpfRegR2  = 2
	bpfRegR3  = 3
	bpfRegR4  = 4
	bpfRegR5  = 5
	bpfRegR6  = 6
	bpfRegR7  = 7
	bpfRegR8  = 8
	bpfRegR9  = 9
	bpfRegR10 = 10 // frame pointer (read-only)
)

// Instruction builder helpers

// bpfMovImm: dst = imm (64-bit)
func bpfMovImm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfMov | bpfK, dst: dst, imm: imm}
}

// bpfMovReg: dst = src (64-bit)
func bpfMovReg(dst, src uint8) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfMov | bpfX, dst: dst, src: src}
}

// bpfMovImm32: dst = imm (32-bit)
func bpfMovImm32(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfClassALU | bpfMov | bpfK, dst: dst, imm: imm}
}

// bpfAddImm: dst += imm (64-bit)
func bpfAddImm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfAdd | bpfK, dst: dst, imm: imm}
}

// bpfAddReg: dst += src (64-bit)
func bpfAddReg(dst, src uint8) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfAdd | bpfX, dst: dst, src: src}
}

// bpfSubImm: dst -= imm (64-bit)
func bpfSubImm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfSub | bpfK, dst: dst, imm: imm}
}

// bpfAndImm: dst &= imm (64-bit)
func bpfAndImm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfAnd | bpfK, dst: dst, imm: imm}
}

// bpfAndImm32: dst &= imm (32-bit)
func bpfAndImm32(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfClassALU | bpfAnd | bpfK, dst: dst, imm: imm}
}

// bpfLShImm: dst <<= imm (64-bit)
func bpfLShImm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfLSH | bpfK, dst: dst, imm: imm}
}

// bpfRShImm: dst >>= imm (64-bit)
func bpfRShImm(dst uint8, imm int32) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfRSH | bpfK, dst: dst, imm: imm}
}

// bpfOrReg: dst |= src (64-bit)
func bpfOrReg(dst, src uint8) bpfInsn {
	return bpfInsn{code: bpfALU64 | bpfOr | bpfX, dst: dst, src: src}
}

// bpfEndianBE: dst = htobe(dst) for the given size in bits (16, 32, or 64).
// On little-endian hosts this byte-swaps; on big-endian it is a no-op.
// Also serves as ntohs/ntohl when converting from network byte order.
func bpfEndianBE(dst uint8, size int32) bpfInsn {
	return bpfInsn{code: bpfClassALU | bpfEnd | bpfToBE, dst: dst, imm: size}
}

// bpfEndianLE: dst = htole(dst) for the given size in bits (16, 32, or 64).
func bpfEndianLE(dst uint8, size int32) bpfInsn {
	return bpfInsn{code: bpfClassALU | bpfEnd | bpfToLE, dst: dst, imm: size}
}

// bpfLoadMem loads from memory: dst = *(size *)(src + off)
func bpfLoadMem(size uint8, dst, src uint8, off int16) bpfInsn {
	return bpfInsn{code: bpfClassLDX | bpfMEM | size, dst: dst, src: src, off: off}
}

// bpfStoreMem stores to memory: *(size *)(dst + off) = src
func bpfStoreMem(size uint8, dst, src uint8, off int16) bpfInsn {
	return bpfInsn{code: bpfClassSTX | bpfMEM | size, dst: dst, src: src, off: off}
}

// bpfStoreImm stores immediate to memory: *(size *)(dst + off) = imm
func bpfStoreImm(size uint8, dst uint8, off int16, imm int32) bpfInsn {
	return bpfInsn{code: bpfClassST | bpfMEM | size, dst: dst, off: off, imm: imm}
}

// bpfLoadMapFD loads a map fd using a 2-instruction LD_IMM64 sequence.
// Returns two instructions that must appear consecutively.
// The first instruction uses BPF_PSEUDO_MAP_FD in src_reg.
func bpfLoadMapFD(dst uint8, fd int32) [2]bpfInsn {
	return [2]bpfInsn{
		{code: bpfClassLD | bpfDW | bpfIMM, dst: dst, src: bpfPseudoMapFD, imm: fd},
		{code: 0, imm: 0}, // continuation of 128-bit load
	}
}

// bpfJmpImm: conditional jump on register vs immediate
func bpfJmpImm(op uint8, dst uint8, imm int32, off int16) bpfInsn {
	return bpfInsn{code: bpfClassJMP | op | bpfK, dst: dst, off: off, imm: imm}
}

// bpfJmpReg: conditional jump on register vs register
func bpfJmpReg(op uint8, dst, src uint8, off int16) bpfInsn {
	return bpfInsn{code: bpfClassJMP | op | bpfX, dst: dst, src: src, off: off}
}

// bpfJmpA: unconditional jump
func bpfJmpA(off int16) bpfInsn {
	return bpfInsn{code: bpfClassJMP | bpfJA, off: off}
}

// bpfCallHelper: call BPF helper function
func bpfCallHelper(helperID int32) bpfInsn {
	return bpfInsn{code: bpfClassJMP | bpfCall, imm: helperID}
}

// bpfExitInsn: return from BPF program
func bpfExitInsn() bpfInsn {
	return bpfInsn{code: bpfClassJMP | bpfExit}
}
