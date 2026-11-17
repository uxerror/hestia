// Package testelf builds tiny ELF images for tests (never executed).
package testelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
)

// Opts describes the image.
type Opts struct {
	Machine elf.Machine // default EM_X86_64
	Dynamic bool        // add a PT_INTERP header (dynamically linked)
	Class32 bool
	Payload []byte // trailing bytes (to make images differ)
}

// Build returns a minimal ELF64 little-endian executable.
func Build(o Opts) []byte {
	if o.Machine == 0 {
		o.Machine = elf.EM_X86_64
	}
	phnum := 1
	if o.Dynamic {
		phnum = 2
	}
	var b bytes.Buffer
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1, byte(elf.ELFOSABI_NONE)}
	if o.Class32 {
		ident[4] = byte(elf.ELFCLASS32)
	}
	b.Write(ident[:])
	w := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	w(uint16(elf.ET_EXEC))
	w(uint16(o.Machine))
	w(uint32(1))
	w(uint64(0x400000)) // entry
	w(uint64(64))       // phoff
	w(uint64(0))        // shoff
	w(uint32(0))        // flags
	w(uint16(64))       // ehsize
	w(uint16(56))       // phentsize
	w(uint16(phnum))
	w(uint16(64)) // shentsize
	w(uint16(0))  // shnum
	w(uint16(0))  // shstrndx
	ph := func(typ elf.ProgType) {
		w(uint32(typ))
		w(uint32(5)) // flags
		w(uint64(0)) // off
		w(uint64(0x400000))
		w(uint64(0x400000))
		w(uint64(0))
		w(uint64(0))
		w(uint64(0x1000))
	}
	ph(elf.PT_LOAD)
	if o.Dynamic {
		ph(elf.PT_INTERP)
	}
	b.Write(o.Payload)
	return b.Bytes()
}
