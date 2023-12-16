package main

/*
import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"plugin"
	"strings"
	"syscall"
	"unsafe"
)

const (
	_PAGE_LENGTH     = 0x4000
	_MMAP_TEXT_FLAGS = syscall.MAP_FIXED | syscall.MAP_SHARED
	_MMAP_DATA_FLAGS = syscall.MAP_FIXED | syscall.MAP_ANONYMOUS | syscall.MAP_PRIVATE
)

type ElfHashTable struct {
	// nbucket uint32
	// nchain uint32
	buckets []uint32
	chains  []uint32
}

type HenVPluginLoader struct {
	hashtab   ElfHashTable
	symtab    []elf.Sym64
	strtab    string
	imagebase uintptr
}

func jitshmCreate(addr uintptr, length int, flags uint64) (fd int, err error) {
	// int jitshm_create(uintptr_t addr, size_t length, uint64_t flags)
	h, _, errno := syscall.Syscall(syscall.SYS_JITSHM_CREATE, addr, uintptr(length), uintptr(flags))
	if errno != 0 {
		err = errno
	}
	fd = int(h)
	return
}

func mmap(addr uintptr, len, prot, flags, fd int) (res uintptr, err error) {
	res, _, errno := syscall.Syscall6(syscall.SYS_MMAP, addr, uintptr(len), uintptr(prot), uintptr(flags), uintptr(fd), 0)
	if errno != 0 {
		err = errno
	}
	return
}

func munmap(addr uintptr, len uint64) (n int, err error) {
	res, _, errno := syscall.Syscall(syscall.SYS_MUNMAP, addr, uintptr(len), 0)
	if errno != 0 {
		err = errno
	}
	n = int(res)
	return
}

func toVirtualAddress(textVaddr, textOffset, imagebase, addr uintptr) uintptr {
	if addr >= textVaddr {
		addr -= textVaddr + textOffset
	}
	return imagebase + addr
}

func sizeAlign(size uint, alignment uint) uint {
	return (((size) + ((alignment) - 1)) & ^((alignment) - 1))
}

func pageAlign(length uint) uint {
	return sizeAlign(length, _PAGE_LENGTH)
}

func toMmapProt(flags elf.ProgFlag) (res uint32) {
	if (flags & elf.PF_X) != 0 {
		res |= syscall.PROT_EXEC
	}
	if (flags & elf.PF_R) != 0 {
		res |= syscall.PROT_READ
	}
	if (flags & elf.PF_W) != 0 {
		res |= syscall.PROT_WRITE
	}
	return
}

func toFileOffset(textVaddr, textOffset, addr uintptr) int {
	if textVaddr == 0 {
		return int(addr)
	}
	if addr >= textVaddr {
		return int(addr - textVaddr + textOffset)
	}
	return int(addr)
}

func (ldr *HenVPluginLoader) OpenPlugin(name string) (p *plugin.ProsperoPlugin, err error) {
	p = &plugin.ProsperoPlugin{
		Mappings: make([]plugin.MappedAddress, 0),
		Jit:      -1,
	}
	// TODO load elf and call go.link.addmoduledata

	// these elfs aren't built correctly but idgaf
	fp, err := elf.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fp != nil {
			fp.Close()
		}
	}()

	syms, err := fp.Symbols()
	if err != nil {
		return nil, err
	}

	res := make(map[string]uintptr, len(syms))

	for i := range syms {
		res[syms[i].Name] = uintptr(syms[i].Value)
	}

	phdrs := fp.Progs
	text := -1
	dynamic := -1
	length := 0
	for i := range phdrs {
		if phdrs[i].Type == elf.PT_LOAD {
			length += int(phdrs[i].Memsz)
			if text == -1 && phdrs[i].Flags&elf.PF_X != 0 {
				text = i
				break
			}
		} else if phdrs[i].Type == elf.PT_DYNAMIC {
			dynamic = i
		}
	}

	length = int(pageAlign(uint(length)))

	const flags = syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC
	jit, err := jitshmCreate(0, int(phdrs[text].Memsz), flags)
	if err != nil {
		return nil, err
	}

	p.Jit = jit

	defer func() {
		if err != nil {
			p.Close()
		}
	}()

	imagebase, err := mmap(0, length, syscall.PROT_READ, syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE, -1)
	if err != nil {
		return nil, err
	}
	_, err = munmap(imagebase, uint64(length))
	if err != nil {
		return nil, err
	}

	textVaddr := uintptr(phdrs[text].Vaddr)
	textOffset := uintptr(phdrs[text].Off)

	for i := range phdrs {
		phdr := phdrs[i]
		if phdr.Type != elf.PT_LOAD {
			continue
		}
		addr := toVirtualAddress(textVaddr, textOffset, imagebase, uintptr(phdrs[i].Paddr))
		size := pageAlign(uint(phdrs[i].Memsz))
		prot := toMmapProt(phdrs[i].Flags)

		var fd int
		var flags uint32
		if i == text {
			fd = jit
			flags = _MMAP_DATA_FLAGS // _MMAP_TEXT_FLAGS
		} else {
			fd = -1
			flags = _MMAP_DATA_FLAGS
		}

		res, err2 := mmap(addr, int(size), int(prot), int(flags), fd)
		if err2 != nil {
			err = err2
			return
		}

		p.Mappings = append(p.Mappings, plugin.MappedAddress{Addr: addr, Length: uintptr(size)})

		mem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), phdr.Filesz)
		_, err = io.Copy(bytes.NewBuffer(mem), phdr.Open())
		if err != nil {
			return
		}

		if uintptr(res) != addr {
			err = fmt.Errorf("mmap did not give the requested address requested %#08x received %#08x", addr, res)
			return
		}
	}

	buf := make([]byte, phdrs[dynamic].Filesz)
	n := phdrs[dynamic].Filesz / 0x10
	_, err = phdrs[dynamic].Open().Read(buf)
	if err != nil {
		return
	}

	err = fp.Close()
	fp = nil
	if err != nil {
		return
	}

	dyntab := unsafe.Slice((*elf.Dyn64)(unsafe.Pointer(&buf[0])), n)
	var relasz int
	var relaoffset int
	for i := range dyntab {
		switch dyntab[i].Tag {
		case int64(elf.DT_RELA):
			relaoffset = toFileOffset(textVaddr, textOffset, uintptr(dyntab[i].Val))
		case int64(elf.DT_RELASZ):
			relasz = int(dyntab[i].Val)
		}
	}
	if relasz > 0 {
		f, err2 := os.Open(name)
		if err2 != nil {
			err = err2
			return
		}

		defer f.Close()

		buf = make([]byte, relasz)
		_, err = f.Seek(int64(relaoffset), io.SeekStart)
		if err != nil {
			return
		}
		_, err = f.Read(buf)
		if err != nil {
			return
		}
		relatab := unsafe.Slice((*elf.Rela64)(unsafe.Pointer(&buf[0])), relasz/0x18)
		for i := range relatab {
			t := elf.R_TYPE64(relatab[i].Info)
			if t != uint32(elf.R_X86_64_RELATIVE) {
				err = fmt.Errorf("unexpected relocation type %v", t)
				return
			}
			ptr := unsafe.Pointer(toVirtualAddress(textVaddr, textOffset, imagebase, uintptr(relatab[i].Off)))
			*(*uintptr)(ptr) = toVirtualAddress(textVaddr, textOffset, imagebase, uintptr(relatab[i].Addend))
		}
	}

	syscall.Syscall(Syscall.SYS_MMAP)
	return
}

func (ldr *HenVPluginLoader) LookupSymbol(name string) uintptr {
	hash := hashSymbol(name)

	nbucket := len(ldr.hashtab.buckets)

	for i := ldr.hashtab.buckets[hash%uint32(nbucket)]; i != 0; i = ldr.hashtab.chains[i] {
		str := ldr.strtab[ldr.symtab[i].Name:]
		index := strings.IndexByte(str, 0)
		if index == -1 {
			return 0
		}
		if name == str[:index] {
			return uintptr(ldr.symtab[i].Value) + ldr.imagebase
		}
	}

	return 0
}

func newElfHashTable(data unsafe.Pointer) ElfHashTable {
	nbucket := *(*uint32)(data)
	nchain := *(*uint32)(unsafe.Add(data, 4))
	buckets := (*uint32)(unsafe.Add(data, 8))
	chains := (*uint32)(unsafe.Add(data, 8+(4*nbucket)))
	return ElfHashTable{
		buckets: unsafe.Slice(buckets, nbucket),
		chains:  unsafe.Slice(chains, nchain),
	}
}

func hashSymbol(sym string) uint32 {
	var h uint32
	for i := range sym {
		h = (h << 4) + uint32(sym[i])
		g := h & 0xf0000000
		if g != 0 {
			h ^= g >> 24
		}
		h &= ^g
	}
	return h
}

*/
