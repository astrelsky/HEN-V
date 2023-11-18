package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"log"
	"unsafe"
)

var (
	ErrBadElfMagic     = errors.New("ELF MAGIC check failed")
	ErrBadElfByteOrder = errors.New("ELF must be little endian")
	ErrBadElfClass     = errors.New("ELF must be 64 bit")
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

type ElfHashTable struct {
	// nbucket uint32
	// nchain uint32
	buckets []uint32
	chains  []uint32
}

type GnuHashTable struct {
	// nbucket uint32
	// symbase uint32
	// bloom_size uint32
	// bloom_shift uint32
	// blooms [bloom_size]uintptr
	// buckets [nbucket]uint32
	// chains []uint32 // use nbucket
	blooms     []uintptr
	buckets    []uint32
	chains     []uint32
	symbase    uint32
	bloomshift uint32
}

type Elf struct {
	data      []byte
	phdrs     []Elf64_Phdr
	reltab    []Elf64_Rela
	plttab    []Elf64_Rela
	symtab    []Elf64_Sym
	ehdr      *Elf64_Ehdr
	dyntab    *Elf64_Dyn
	hashtab   *ElfHashTable
	gnuhash   *GnuHashTable
	strtab    *uint8
	textIndex int
}

func NewElf(data []byte) (Elf, error) {
	err := checkElf(data)
	if err != nil {
		return Elf{}, err
	}

	ehdr := (*Elf64_Ehdr)(unsafe.Pointer(&data[0]))
	phdrs := unsafe.Slice((*Elf64_Phdr)(unsafe.Pointer(&data[ehdr.Phoff])), ehdr.Phnum)
	elf := Elf{
		data:      data,
		phdrs:     phdrs,
		ehdr:      ehdr,
		textIndex: -1,
	}

	err = parseDynamicTable(&elf)

	return elf, err
}

func newElfHashTable(data unsafe.Pointer) *ElfHashTable {
	nbucket := *(*uint32)(data)
	nchain := *(*uint32)(unsafe.Add(data, 4))
	buckets := (*uint32)(unsafe.Add(data, 8))
	chains := (*uint32)(unsafe.Add(data, 8+(4*nbucket)))
	return &ElfHashTable{
		buckets: unsafe.Slice(buckets, nbucket),
		chains:  unsafe.Slice(chains, nchain),
	}
}

func newGnuHashTable(data unsafe.Pointer) *GnuHashTable {
	nbucket := *(*uint32)(data)
	symbase := *(*uint32)(unsafe.Add(data, 4))
	bloomsize := *(*uint32)(unsafe.Add(data, 8))
	bloomshift := *(*uint32)(unsafe.Add(data, 12))
	pos := uint32(16)
	blooms := unsafe.Slice((*uintptr)(unsafe.Pointer(unsafe.Add(data, pos))), bloomsize)
	pos += 8 * bloomsize
	buckets := unsafe.Slice((*uint32)(unsafe.Pointer(unsafe.Add(data, pos))), nbucket)
	pos += 4 * nbucket
	chains := unsafe.Slice((*uint32)(unsafe.Pointer(unsafe.Add(data, pos))), nbucket)
	return &GnuHashTable{
		blooms:     blooms,
		buckets:    buckets,
		chains:     chains,
		symbase:    symbase,
		bloomshift: bloomshift,
	}
}

func parseDynamicTable(ldr *Elf) error {
	dyn, err := findDynamicTable(ldr)
	if err != nil {
		return err
	}

	ldr.dyntab = dyn

	var symtabOffset int
	var reltabSize int
	var plttabSize int
	var reltab unsafe.Pointer
	var plttab unsafe.Pointer
	for ; dyn.Tag() != elf.DT_NULL; dyn = dyn.Next() {
		switch dyn.Tag() {
		case elf.DT_RELA:
			reltab = ldr.faddr(dyn.Value())
		case elf.DT_RELASZ:
			const size = int(unsafe.Sizeof(Elf64_Rela{}))
			reltabSize = dyn.Value() / size
		case elf.DT_JMPREL:
			plttab = ldr.faddr(dyn.Value())
		case elf.DT_PLTRELSZ:
			const size = int(unsafe.Sizeof(Elf64_Rela{}))
			plttabSize = dyn.Value() / size
		case elf.DT_SYMTAB:
			symtabOffset = dyn.Value()
		case elf.DT_STRTAB:
			ldr.strtab = (*byte)(ldr.faddr(dyn.Value()))
		case elf.DT_HASH:
			ldr.hashtab = newElfHashTable(ldr.faddr(dyn.Value()))
		case elf.DT_GNU_HASH:
			ldr.gnuhash = newGnuHashTable(ldr.faddr(dyn.Value()))
		default:
		}
	}

	if symtabOffset != 0 {
		// just fake a symtab size to make a slice
		symtab := ldr.faddr(symtabOffset)
		symtabsize := (len(ldr.data) - symtabOffset) / int(unsafe.Sizeof(Elf64_Sym{}))
		ldr.symtab = unsafe.Slice((*Elf64_Sym)(symtab), symtabsize)
	}

	if reltab != nil {
		ldr.reltab = unsafe.Slice((*Elf64_Rela)(reltab), reltabSize)
	}

	if plttab != nil {
		ldr.plttab = unsafe.Slice((*Elf64_Rela)(plttab), plttabSize)
	}

	return nil
}

func checkElf(data []byte) error {
	if string(data[:len(elf.ELFMAG)]) != elf.ELFMAG {
		return ErrBadElfMagic
	}

	ehdr := (*Elf64_Ehdr)(unsafe.Pointer(&data[0]))
	abi := ehdr.GetOsAbi()
	if abi != elf.ELFOSABI_NONE && abi != elf.ELFOSABI_FREEBSD {
		return fmt.Errorf("Unexpected ei_osabi %s", abi)
	}

	machine := ehdr.GetMachine()

	if machine != elf.EM_X86_64 {
		return fmt.Errorf("Unexpected e_machine %s", machine)
	}

	if ehdr.GetClass() != elf.ELFCLASS64 {
		return ErrBadElfClass
	}

	if ehdr.GetData() != elf.ELFDATA2LSB {
		return ErrBadElfByteOrder
	}

	return nil
}

func (ehdr *Elf64_Ehdr) GetOsAbi() elf.OSABI {
	return elf.OSABI(ehdr.Ident[elf.EI_OSABI])
}

func (ehdr *Elf64_Ehdr) GetMachine() elf.Machine {
	return elf.Machine(ehdr.Machine)
}

func (ehdr *Elf64_Ehdr) GetClass() elf.Class {
	return elf.Class(ehdr.Ident[elf.EI_CLASS])
}

func (ehdr *Elf64_Ehdr) GetData() elf.Data {
	return elf.Data(ehdr.Ident[elf.EI_DATA])
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

func (ldr *Elf) getDataAt(offset int) unsafe.Pointer {
	return unsafe.Add(unsafe.Pointer(&ldr.data[0]), offset)
}

func (ldr *Elf) getTextHeader() *Elf64_Phdr {
	if ldr.textIndex != -1 {
		return &ldr.phdrs[ldr.textIndex]
	}

	for i := range ldr.phdrs {
		if (ldr.phdrs[i].Flags() & elf.PF_X) != 0 {
			if ldr.phdrs[i].Paddr <= ldr.ehdr.Entry && (ldr.phdrs[i].Paddr+Elf64_Addr(ldr.phdrs[i].Filesz)) < ldr.ehdr.Entry {
				ldr.textIndex = i
				return &ldr.phdrs[ldr.textIndex]
			}
		}
	}

	log.Println("text section not found")
	return nil
}

func findDynamicTable(ldr *Elf) (*Elf64_Dyn, error) {

	for i := range ldr.phdrs {
		if ldr.phdrs[i].Type() == elf.PT_DYNAMIC {
			return (*Elf64_Dyn)(ldr.getDataAt(int(ldr.phdrs[i].Offset))), nil
		}
	}

	return nil, ErrNoDynamicTable
}

func (ldr *Elf) toFileOffset(addr int) int {
	text := ldr.getTextHeader()
	if Elf64_Addr(addr) >= text.Vaddr {
		return int(Elf64_Addr(addr) - text.Vaddr + Elf64_Addr(text.Offset))
	}
	return addr
}

func (ldr *Elf) faddr(addr int) unsafe.Pointer {
	addr = ldr.toFileOffset(addr)
	return unsafe.Pointer(&ldr.data[addr])
}

func (ldr *Elf) getString(i int) string {
	index := bytes.IndexByte(ldr.data[i:], 0)
	if index == -1 {
		log.Printf("missing null terminator at %#08x\n", i)
		return ""
	}
	return string(ldr.data[i : i+index])
}
