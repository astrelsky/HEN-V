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
	ErrNoDlSym                    = errors.New("failed to resolve sceKernelDlsym")
	ErrProcessNotReady            = errors.New("elf_start process is not ready (FS is 0)")
)

const (
	_STACK_ALIGN        = 0x10
	_PAGE_LENGTH        = 0x4000
	_MMAP_TEXT_FLAGS    = syscall.MAP_FIXED | syscall.MAP_SHARED
	_MMAP_DATA_FLAGS    = syscall.MAP_FIXED | syscall.MAP_ANONYMOUS | syscall.MAP_PRIVATE
	_PAYLOAD_ARGS_SIZE  = int(0x30)
	IPV6_2292PKTOPTIONS = 25
)

type ElfLoader struct {
	data         []byte
	tracer       Tracer
	resolver     Resolver
	textIndex    int
	dynamicIndex int
	reltab       []Elf64_Rela
	plttab       []Elf64_Rela
	symtab       []Elf64_Sym
	strtab       *uint8
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
	}
}

func (ldr *ElfLoader) toFileOffset(addr int) int {
	text := ldr.getTextHeader()
	if Elf64_Addr(addr) >= text.Vaddr {
		return int(Elf64_Addr(addr) - text.Vaddr + Elf64_Addr(text.Offset))
	}
	return addr
}

func (ldr *ElfLoader) faddr(addr int) unsafe.Pointer {
	addr = ldr.toFileOffset(addr)
	return unsafe.Pointer(&ldr.data[addr])
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

		lib := ldr.getString(dyn.Value())
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

func (ldr *ElfLoader) getSymbolAddress(rel *Elf64_Rela) (uintptr, error) {
	name := ldr.getString(int(ldr.symtab[rel.Symbol()].Name))
	libsym := ldr.resolver.LookupSymbol(name)
	if libsym == 0 {
		return 0, fmt.Errorf("failed to find library symbol %s", name)
	}
	return libsym, nil
}

func (ldr *ElfLoader) processPltRelocations() error {
	if ldr.plttab == nil {
		return nil
	}

	for i := range ldr.plttab {
		plt := &ldr.plttab[i]
		if plt.Type() != elf.R_X86_64_JMP_SLOT {
			sym := &ldr.symtab[plt.Symbol()]
			name := ldr.getString(int(sym.Name))
			return fmt.Errorf("unexpected relocation type %s for symbol %s\n", plt.Type().String(), name)
		}

		libsym, err := ldr.getSymbolAddress(plt)
		if err != nil {
			log.Println(err)
			return err
		}
		*(*uintptr)(ldr.faddr(int(plt.r_offset))) = libsym
	}

	return nil
}

func (ldr *ElfLoader) processRelaRelocations() error {
	if ldr.reltab == nil {
		return nil
	}

	for i := range ldr.reltab {
		rel := &ldr.reltab[i]
		switch rel.Type() {
		case elf.R_X86_64_64:
			// symbol + addend
			libsym, err := ldr.getSymbolAddress(rel)
			if err != nil {
				log.Println(err)
				return err
			}
			*(*uintptr)(ldr.faddr(int(rel.r_offset))) = libsym + uintptr(rel.r_addend)

		case elf.R_X86_64_GLOB_DAT:
			// symbol
			libsym, err := ldr.getSymbolAddress(rel)
			if err != nil {
				log.Println(err)
				return err
			}
			*(*uintptr)(ldr.faddr(int(rel.r_offset))) = libsym
		case elf.R_X86_64_RELATIVE:
			// imagebase + addend
			*(*uintptr)(ldr.faddr(int(rel.r_offset))) = ldr.imagebase + uintptr(rel.r_addend)

		case elf.R_X86_64_JMP_SLOT:
			// edge case where the dynamic relocation sections are merged
			libsym, err := ldr.getSymbolAddress(rel)
			if err != nil {
				log.Println(err)
				return err
			}
			*(*uintptr)(ldr.faddr(int(rel.r_offset))) = libsym
		default:
			sym := &ldr.symtab[rel.Symbol()]
			name := ldr.getString(int(sym.Name))
			return fmt.Errorf("unexpected relocation type %s for symbol %s\n", rel.Type().String(), name)

		}
	}
	return nil
}

func (ldr *ElfLoader) processRelocations() error {
	err := ldr.processPltRelocations()
	if err != nil {
		return err
	}
	return ldr.processRelaRelocations()
}

func createReadWriteSockets(proc KProc, sockets [2]int) error {
	newtbl := proc.GetFd().GetFdTbl()
	sock := uintptr(newtbl.GetFileData(sockets[0]))
	if sock == 0 {
		return errors.New("sock == 0")
	}
	kwrite32(sock, 0x100)
	pcb := uintptr(kread64(sock + 0x18))
	if pcb == 0 {
		return errors.New("master pcb == 0")
	}
	master_inp6_outputopts := uintptr(kread64(pcb + 0x120))
	if master_inp6_outputopts == 0 {
		return errors.New("master_inp6_outputopts == 0")
	}
	sock = uintptr(newtbl.GetFileData(sockets[1]))
	kwrite32(sock, 0x100)
	pcb = uintptr(kread64(sock + 0x18))
	if pcb == 0 {
		return errors.New("victim pcb == 0")
	}
	victim_inp6_outputopts := kread64(pcb + 0x120)
	if victim_inp6_outputopts == 0 {
		return errors.New("victim_inp6_outputopts == 0")
	}
	kwrite64(master_inp6_outputopts+0x10, victim_inp6_outputopts+0x10)
	kwrite32(master_inp6_outputopts+0xc0, 0x13370000)
	return nil
}

func (ldr *ElfLoader) setupKernelRW() (addr uintptr, err error) {

	var files [4]int32
	fd, err := ldr.tracer.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		log.Println(err)
		return
	}
	files[0] = int32(fd)

	fd, err = ldr.tracer.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		log.Println(err)
		return
	}

	files[1] = int32(fd)

	log.Printf("master socket: %d\n", files[0])
	log.Printf("victim socket: %d\n", files[1])

	if files[0] == -1 || files[1] == -1 {
		return
	}

	pipes, err := ldr.tracer.Pipe()
	if err != nil {
		log.Println(err)
		return
	}

	files[2] = int32(pipes[0])
	files[3] = int32(pipes[1])

	log.Printf("rw pipes: %d, %d\n", files[2], files[3])

	buf := [...]uint32{20, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 0, 0, 0}
	const bufSize = int(unsafe.Sizeof(buf))

	err = ldr.tracer.Setsockopt(
		int(files[0]),
		syscall.IPPROTO_IPV6,
		IPV6_2292PKTOPTIONS,
		unsafe.Pointer(&buf[0]),
		bufSize,
	)

	if err != nil {
		log.Println(err)
		return
	}

	buf = [6]uint32{}

	err = ldr.tracer.Setsockopt(
		int(files[1]),
		syscall.IPPROTO_IPV6,
		syscall.IPV6_PKTINFO,
		unsafe.Pointer(&buf[0]),
		bufSize-4,
	)

	if err != nil {
		log.Println(err)
		return
	}

	proc := ldr.getProc()

	err = createReadWriteSockets(proc, [2]int{int(files[0]), int(files[1])})
	if err != nil {
		log.Println(err)
		return
	}

	newtbl := proc.GetFd().GetFdTbl()
	pipeaddr := uintptr(kread64(newtbl.GetFile(int(files[2]))))

	var regs Reg
	err = ldr.tracer.GetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return
	}

	const fileSize = int(unsafe.Sizeof(files))
	regs.Rsp -= int64(fileSize)
	newFiles := regs.Rsp
	_, err = UserlandCopyinUnsafe(ldr.pid, uintptr(newFiles), unsafe.Pointer(&files[0]), fileSize)
	if err != nil {
		log.Println(err)
		return
	}

	regs.Rsp -= int64(4 - _PAYLOAD_ARGS_SIZE)
	rsp := regs.Rsp
	err = ldr.tracer.SetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return
	}

	dlsym := ldr.resolver.LookupSymbol("sceKernelDlsym")
	if dlsym == 0 {
		return 0, ErrNoDlSym
	}

	result := [6]uintptr{
		dlsym,
		uintptr(newFiles + 8),
		uintptr(newFiles),
		pipeaddr,
		GetKernelBase(),
		uintptr(rsp + int64(_PAYLOAD_ARGS_SIZE)),
	}

	UserlandCopyinUnsafe(ldr.pid, uintptr(rsp), unsafe.Pointer(&result[0]), _PAYLOAD_ARGS_SIZE)
	addr = uintptr(rsp)
	return
}

func (ldr *ElfLoader) load() error {
	phdrs := ldr.getProgramHeaders()
	for i := range phdrs {
		phdr := &phdrs[i]
		if isLoadable(phdr) {
			vaddr := ldr.toVirtualAddress(uintptr(phdr.Paddr))
			_, err := UserlandCopyin(ldr.pid, vaddr, ldr.data[phdr.Offset:phdr.Filesz])
			if err != nil {
				log.Println(err)
				return err
			}
		}
	}
	return nil
}

func correctRsp(regs *Reg) {
	mask := ^(_STACK_ALIGN - 1)
	regs.Rsp = ((regs.Rsp & int64(mask)) - 8)
}

func (ldr *ElfLoader) start(args uintptr) error {
	log.Printf("imagebase: %#08x\n", ldr.imagebase)
	var regs Reg
	err := ldr.tracer.GetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return err
	}
	if regs.Fs == 0 {
		return ErrProcessNotReady
	}

	correctRsp(&regs)
	regs.Rdi = int64(args)
	entry := uintptr(ldr.getElfHeader().Entry)
	regs.Rip = int64(ldr.toVirtualAddress(entry))
	err = ldr.tracer.SetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return err
	}

	// it will run on detatch
	log.Println("great success")
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
	err = ldr.processRelocations()
	if err != nil {
		log.Println(err)
		return err
	}

	log.Println("setting up kernel rw")
	args, err := ldr.setupKernelRW()
	if err != nil {
		log.Println(err)
		return err
	}

	log.Println("loading elf into memory")
	err = ldr.load()
	if err != nil {
		log.Println(err)
		return err
	}

	log.Println("starting")
	return ldr.start(args)
}
