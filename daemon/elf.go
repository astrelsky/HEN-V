package main

import (
	"debug/elf"
	"unsafe"
)

type Elf64_Addr uint64
type Elf64_Half uint16
type Elf64_Off uint64
type Elf64_Sword int32
type Elf64_Sxword int64
type Elf64_Word uint32
type Elf64_Lword uint64
type Elf64_Xword uint64

type Elf64_Ehdr struct {
	Ident     [elf.EI_NIDENT]byte
	Type      Elf64_Half
	Machine   Elf64_Half
	Version   Elf64_Word
	Entry     Elf64_Addr
	Phoff     Elf64_Off
	Shoff     Elf64_Off
	Flags     Elf64_Word
	Ehsize    Elf64_Half
	Phentsize Elf64_Half
	Phnum     Elf64_Half
	Shentsize Elf64_Half
	Shnum     Elf64_Half
	Shstrndx  Elf64_Half
}

type Elf64_Phdr struct {
	p_type  Elf64_Word
	p_flags Elf64_Word
	Offset  Elf64_Off
	Vaddr   Elf64_Addr
	Paddr   Elf64_Addr
	Filesz  Elf64_Xword
	Memsz   Elf64_Xword
	Align   Elf64_Xword
}

type Elf64_Dyn struct {
	d_tag   int
	d_value uint64
}

type Elf64_Sym struct {
	Name  Elf64_Word
	Info  byte
	Other byte
	Shndx Elf64_Half
	Value Elf64_Addr
	Size  Elf64_Xword
}

type Elf64_Rela struct {
	r_offset Elf64_Addr
	r_info   Elf64_Xword
	r_addend Elf64_Sxword
}

func (ehdr *Elf64_Ehdr) GetOsAbi() elf.OSABI {
	return elf.OSABI(ehdr.Ident[elf.EI_OSABI])
}

func (phdr *Elf64_Phdr) Type() elf.ProgType {
	return elf.ProgType(phdr.p_type)
}

func (phdr *Elf64_Phdr) Flags() elf.ProgFlag {
	return elf.ProgFlag(phdr.p_flags)
}

func (dyn *Elf64_Dyn) Tag() elf.DynTag {
	return elf.DynTag(dyn.d_tag)
}

func (dyn *Elf64_Dyn) Value() int {
	return int(dyn.d_value)
}

func (dyn *Elf64_Dyn) Next() *Elf64_Dyn {
	if dyn.Tag() == elf.DT_NULL {
		panic("dynamic table iterator overrun")
	}
	const size = unsafe.Sizeof(Elf64_Dyn{})
	return (*Elf64_Dyn)(unsafe.Add(unsafe.Pointer(dyn), size))
}

func (rela *Elf64_Rela) Symbol() int {
	return int(rela.r_info) >> 32
}

func (rela *Elf64_Rela) Type() elf.R_X86_64 {
	return elf.R_X86_64(uint32(rela.r_info))
}
