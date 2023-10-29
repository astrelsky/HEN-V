package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"log"
	"strings"
	"syscall"
	"unsafe"
)

var (
	ErrNoDynamicTable             = errors.New("no dynamic table")
	ErrNoLibSysModule             = errors.New("failed to get libSceSysmodule")
	ErrNoLoadModuleByNameInternal = errors.New("failed to resolve sceSysmoduleLoadModuleByNameInternal")
	ErrNoLoadModuleInternal       = errors.New("failed to resolve sceSysmoduleLoadModuleInternal")
)

const (
	_PAGE_LENGTH     = 0x4000
	_MMAP_TEXT_FLAGS = syscall.MAP_FIXED | syscall.MAP_SHARED
	_MMAP_DATA_FLAGS = syscall.MAP_FIXED | syscall.MAP_ANONYMOUS | syscall.MAP_PRIVATE
)

type ElfLoader struct {
	data         []byte
	tracer       Tracer
	resolver     Resolver
	textIndex    int
	dynamicIndex int
	reltab       int
	reltabSize   uintptr
	plttab       int
	plttabSize   uintptr
	symtab       int
	strtab       int
	imagebase    uintptr
	proc         KProc
	pid          int
}

func NewElfLoader(pid int, data []byte) ElfLoader {
	return ElfLoader{
		data:         data,
		pid:          pid,
		textIndex:    -1,
		dynamicIndex: -1,
		reltab:       -1,
		plttab:       -1,
	}
}

func (ldr *ElfLoader) getProc() KProc {
	if ldr.proc != 0 {
		return ldr.proc
	}
	ldr.proc = GetProc(ldr.pid)
	return ldr.proc
}

func (ldr *ElfLoader) getDataAt(offset int) unsafe.Pointer {
	return unsafe.Add(unsafe.Pointer(&ldr.data[0]), offset)
}

func (ldr *ElfLoader) getElfHeader() *Elf64_Ehdr {
	return (*Elf64_Ehdr)(ldr.getDataAt(0))
}

func (ldr *ElfLoader) getProgramHeaders() []Elf64_Phdr {
	elf := ldr.getElfHeader()
	return unsafe.Slice((*Elf64_Phdr)(ldr.getDataAt(int(elf.Phoff))), elf.Phnum)
}

func (ldr *ElfLoader) getDynamicTable() (*Elf64_Dyn, error) {
	phdrs := ldr.getProgramHeaders()
	if ldr.dynamicIndex == 0 {
		return (*Elf64_Dyn)(ldr.getDataAt(int(phdrs[ldr.dynamicIndex].Offset))), nil
	}

	for i := range phdrs {
		if phdrs[i].Type() == elf.PT_DYNAMIC {
			ldr.dynamicIndex = i
			return (*Elf64_Dyn)(ldr.getDataAt(int(phdrs[ldr.dynamicIndex].Offset))), nil
		}
	}

	return nil, ErrNoDynamicTable
}

func (ldr *ElfLoader) processDynamicTable() error {
	dyn, err := ldr.getDynamicTable()
	if err != nil {
		return err
	}
	for ; dyn.Tag() != elf.DT_NULL; dyn = dyn.Next() {
		switch dyn.Tag() {
		case elf.DT_RELA:
			ldr.reltab = dyn.Value()
		case elf.DT_RELASZ:
			const size = unsafe.Sizeof(Elf64_Rela{})
			ldr.reltabSize = uintptr(dyn.Value()) / size
		case elf.DT_JMPREL:
			ldr.plttab = dyn.Value()
		case elf.DT_PLTRELSZ:
			const size = unsafe.Sizeof(Elf64_Rela{})
			ldr.plttabSize = uintptr(dyn.Value()) / size
		case elf.DT_SYMTAB:
			ldr.symtab = dyn.Value()
		case elf.DT_STRTAB:
			ldr.strtab = dyn.Value()
		default:
		}
	}
	return nil
}

func sizeAlign(size uint, alignment uint) uint {
	return (((size) + ((alignment) - 1)) & ^((alignment) - 1))
}

func pageAlign(length uint) uint {
	return sizeAlign(length, _PAGE_LENGTH)
}

func (ldr *ElfLoader) getTextHeader() *Elf64_Phdr {
	phdrs := ldr.getProgramHeaders()
	if ldr.textIndex != -1 {
		return &phdrs[ldr.textIndex]
	}

	ehdr := ldr.getElfHeader()
	for i := range phdrs {
		if (phdrs[i].Flags() & elf.PF_X) != 0 {
			if phdrs[i].Paddr <= ehdr.Entry && (phdrs[i].Paddr+Elf64_Addr(phdrs[i].Filesz)) < ehdr.Entry {
				ldr.textIndex = i
				return &phdrs[ldr.textIndex]
			}
		}
	}

	log.Println("text section not found")
	return nil
}

func (ldr *ElfLoader) getTextSize() uint {
	text := ldr.getTextHeader()
	if text == nil {
		return 0
	}
	return pageAlign(uint(text.Memsz))
}

func isLoadable(phdr *Elf64_Phdr) bool {
	t := phdr.Type()
	return t == elf.PT_LOAD || t == elf.PT_GNU_EH_FRAME
}

func (ldr *ElfLoader) getTotalLoadSize() (size uint) {
	phdrs := ldr.getProgramHeaders()
	for i := range phdrs {
		if isLoadable(&phdrs[i]) {
			if phdrs[i].Align != _PAGE_LENGTH {
				log.Printf("warning phdr with p_paddr %#08x has alignment %#08x\n", phdrs[i].Paddr, phdrs[i].Align)
			}
			size += sizeAlign(uint(phdrs[i].Memsz), uint(phdrs[i].Align))
		}
	}
	return size
}

func (ldr *ElfLoader) toVirtualAddress(addr uintptr) uintptr {
	text := ldr.getTextHeader()
	if text == nil {
		return 0
	}
	if addr >= uintptr(text.Vaddr) {
		addr -= uintptr(text.Vaddr) + uintptr(text.Offset)
	}
	return ldr.imagebase + addr
}

func toMmapProt(phdr *Elf64_Phdr) (res uint32) {
	flags := phdr.Flags()
	if (flags & elf.PF_X) != 0 {
		res |= syscall.PROT_EXEC
	}
	if (flags & elf.PF_R) != 0 {
		res |= syscall.PROT_READ | syscall.PROT_GPU_READ
	}
	if (flags & elf.PF_W) != 0 {
		res |= syscall.PROT_WRITE | syscall.PROT_GPU_WRITE
	}
	return
}

func (ldr *ElfLoader) mapElfMemory() error {
	// we don't need to worry about cleaning up the target process memory on failure
	// because the process will be killed anyway

	textSize := ldr.getTextSize()
	totalSize := ldr.getTotalLoadSize()

	mem, err := ldr.tracer.Mmap(0, uint64(totalSize), syscall.PROT_READ, syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE, -1, 0)
	if err != nil {
		log.Println(err)
		return err
	}

	if mem == -1 {
		err = ldr.tracer.Errno()
		if err != nil {
			log.Println(err)
		}
		return err
	}

	ldr.imagebase = uintptr(mem)

	res, err := ldr.tracer.Munmap(uintptr(mem), uint64(totalSize))
	if err != nil {
		log.Println(err)
		return err
	}

	if res == -1 {
		err = ldr.tracer.Errno()
		if err != nil {
			log.Println(err)
		}
		return err
	}

	// odd that jit_shm doesn't need the GPU PROT flags
	jit, err := ldr.tracer.JitshmCreate(0, uint64(textSize), syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)
	if err != nil {
		log.Println(err)
		return err
	}

	if jit == -1 {
		err = ldr.tracer.Errno()
		if err != nil {
			log.Println(err)
		}
		return err
	}

	phdrs := ldr.getProgramHeaders()

	for i := range phdrs {
		addr := ldr.toVirtualAddress(uintptr(phdrs[i].Paddr))
		size := pageAlign(uint(phdrs[i].Memsz))
		prot := toMmapProt(&phdrs[i])
		var fd int
		var flags uint32
		if i == ldr.textIndex {
			fd = jit
			flags = _MMAP_TEXT_FLAGS
		} else {
			fd = -1
			flags = _MMAP_DATA_FLAGS
		}

		res, err := ldr.tracer.Mmap(addr, uint64(size), int32(prot), int32(flags), fd, 0)
		if err != nil {
			log.Println(err)
			return err
		}
		if res == -1 {
			err = ldr.tracer.Errno()
			if err != nil {
				log.Println(err)
			}
			return err
		}

		if uintptr(res) != addr {
			return fmt.Errorf("tracer_mmap did not give the requested address requested %#08x received 0x#%08x", addr, res)
		}
	}

	return nil
}

func (ldr *ElfLoader) loadLibSysmodule() error {
	proc := ldr.getProc()

	handle := GetModuleHandle(ldr.pid, "libSceSysmodule.sprx")
	if handle == -1 {
		return ErrNoLibSysModule
	}

	lib := proc.GetLib(handle)
	if lib == 0 {
		return ErrNoLibSysModule
	}

	meta := lib.GetMetaData()
	imagebase := lib.GetImageBase()
	err := ldr.resolver.AddLibraryMetaData(imagebase, meta)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

func (ldr *ElfLoader) getString(i int) string {
	index := bytes.IndexByte(ldr.data[i:], 0)
	if index == -1 {
		log.Printf("missing null terminator at %#08x\n", i)
		return ""
	}
	return string(ldr.data[i : i+index])
}

func (ldr *ElfLoader) loadLibrary(id_loader, name_loader, mem uintptr, lib string) (int, error) {
	lib += ".sprx"
	id := syscall.GetInternalPrxId(lib)
	if id != 0 {
		res, err := ldr.tracer.Call(id_loader, id, 0, 0, 0, 0, 0)
		if err != nil {
			log.Println(err)
			return 0, err
		}
		if res == -1 {
			return 0, fmt.Errorf("failed to load lib %s", lib)
		}
	} else {
		_, err := UserlandCopyinUnsafe(ldr.pid, mem, unsafe.Pointer(&([]byte(lib)[0])), len(lib))
		if err != nil {
			log.Println(err)
			return 0, err
		}

		res, err := ldr.tracer.Call(name_loader, mem, 0, 0, 0, 0, 0)
		if err != nil {
			log.Println(err)
			return 0, err
		}
		if res == -1 {
			return 0, fmt.Errorf("failed to load lib %s", lib)
		}
	}
	return GetModuleHandle(ldr.pid, lib), nil
}

func (ldr *ElfLoader) addLibrary(handle int) error {
	proc := ldr.getProc()
	lib := proc.GetLib(handle)
	if lib == 0 {
		return fmt.Errorf("failed to get lib for handle %#x", handle)
	}

	meta := lib.GetMetaData()
	if meta == 0 {
		return fmt.Errorf("failed to get metadata for handle %#x", handle)
	}

	imagebase := lib.GetImageBase()

	return ldr.resolver.AddLibraryMetaData(imagebase, meta)
}

func (ldr *ElfLoader) loadLibraries() error {
	nameLoader := ldr.resolver.LookupSymbol("sceSysmoduleLoadModuleByNameInternal")
	idLoader := ldr.resolver.LookupSymbol("sceSysmoduleLoadModuleInternal")
	if nameLoader == 0 {
		return ErrNoLoadModuleByNameInternal
	}
	if idLoader == 0 {
		return ErrNoLoadModuleInternal
	}
	mem, err := ldr.tracer.Mmap(0, _PAGE_LENGTH, syscall.PROT_READ, syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE, -1, 0)
	if err != nil {
		log.Println(err)
		return err
	}

	if mem == -1 {
		return errors.New("load_libraries tracer_mmap")
	}

	defer ldr.tracer.Munmap(uintptr(mem), _PAGE_LENGTH)

	dyn, err := ldr.getDynamicTable()
	if err != nil {
		log.Println(err)
		return err
	}

	for ; dyn.Tag() != elf.DT_NULL; dyn = dyn.Next() {
		if dyn.Tag() != elf.DT_NEEDED {
			continue
		}

		lib := ldr.getString(ldr.strtab + dyn.Value())
		if strings.HasPrefix(lib, "libkernel") {
			continue
		}
		if strings.HasPrefix(lib, "libc.") || strings.HasPrefix(lib, "libSceLibcInternal") {
			continue
		}

		ext := strings.LastIndexByte(lib, '.')
		if ext != -1 {
			lib = lib[:ext]
		}

		handle, err := ldr.loadLibrary(idLoader, nameLoader, uintptr(mem), lib)
		if err != nil {
			log.Println(err)
			return err
		}

		if handle < 0 {
			return fmt.Errorf("failed to load library %s", lib)
		}

		err = ldr.addLibrary(handle)

		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func (ldr *ElfLoader) Run() error {
	log.Println("processing dynamic table")
	err := ldr.processDynamicTable()
	if err != nil {
		log.Println(err)
		return err
	}

	log.Println("mapping elf memory")
	err = ldr.mapElfMemory()
	if err != nil {
		log.Println(err)
		return err
	}

	log.Println("loading libSysmodule")
	err = ldr.loadLibSysmodule()
	if err != nil {
		log.Println(err)
		return err
	}

	log.Println("loading libraries")
	err = ldr.loadLibraries()
	if err != nil {
		log.Println(err)
		return err
	}

	log.Println("processing relocations")
	// TODO

	return nil
}
