package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
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
	_STACK_ALIGN           = 0x10
	_PAGE_LENGTH           = 0x4000
	_MMAP_TEXT_FLAGS       = syscall.MAP_FIXED | syscall.MAP_SHARED
	_MMAP_DATA_FLAGS       = syscall.MAP_FIXED | syscall.MAP_ANONYMOUS | syscall.MAP_PRIVATE
	_PAYLOAD_ARGS_SIZE     = int(0x30)
	DLSYM_NID          Nid = "LwG8g3niqwA"
)

type ElfLoader struct {
	elf       Elf
	tracer    *Tracer
	resolver  Resolver
	imagebase uintptr
	proc      KProc
	pid       int
	payload   bool
}

type elfReadResult struct {
	buf []byte
	err error
}

func NewElfLoader(pid int, tracer *Tracer, data []byte, payload bool) (ElfLoader, error) {
	var err error
	if tracer == nil {
		tracer, err = NewTracer(pid)
	}
	elf, err := NewElf(data)
	return ElfLoader{
		elf:      elf,
		tracer:   tracer,
		resolver: NewResolver(),
		pid:      pid,
		payload:  payload,
	}, err
}

func (ldr *ElfLoader) toFileOffset(addr int) (int, error) {
	text, err := ldr.getTextHeader()
	if err != nil {
		log.Println(err)
		return 0, err
	}
	if Elf64_Addr(addr) >= text.Vaddr {
		return int(Elf64_Addr(addr) - text.Vaddr + Elf64_Addr(text.Offset)), nil
	}
	return addr, nil
}

func (ldr *ElfLoader) faddr(addr int) (unsafe.Pointer, error) {
	return ldr.elf.faddr(addr)
}

func (ldr *ElfLoader) getProc() KProc {
	if ldr.proc != 0 {
		return ldr.proc
	}
	ldr.proc = GetProc(ldr.pid)
	return ldr.proc
}

func (ldr *ElfLoader) getDynamicTable() *Elf64_Dyn {
	return ldr.elf.dyntab
}

func sizeAlign(size uint, alignment uint) uint {
	return (((size) + ((alignment) - 1)) & ^((alignment) - 1))
}

func pageAlign(length uint) uint {
	return sizeAlign(length, _PAGE_LENGTH)
}

func (ldr *ElfLoader) getTextHeader() (*Elf64_Phdr, error) {
	return ldr.elf.getTextHeader()
}

func (ldr *ElfLoader) getTextSize() (uint, error) {
	text, err := ldr.getTextHeader()
	if err != nil {
		log.Println(err)
		return 0, err
	}
	return pageAlign(uint(text.Memsz)), nil
}

func isLoadable(phdr *Elf64_Phdr) bool {
	t := phdr.Type()
	return t == elf.PT_LOAD || t == elf.PT_GNU_EH_FRAME
}

func (ldr *ElfLoader) getTotalLoadSize() (size uint) {
	phdrs := ldr.elf.phdrs
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

func (ldr *ElfLoader) toVirtualAddress(addr uintptr) (uintptr, error) {
	text, err := ldr.getTextHeader()
	if err != nil {
		log.Println(err)
		return 0, err
	}
	if addr >= uintptr(text.Vaddr) {
		addr -= uintptr(text.Vaddr) + uintptr(text.Offset)
	}
	return ldr.imagebase + addr, nil
}

func toMmapProt(phdr *Elf64_Phdr, payload bool) (res uint32) {
	flags := phdr.Flags()
	if (flags & elf.PF_X) != 0 {
		res |= syscall.PROT_EXEC
	}
	if (flags & elf.PF_R) != 0 {
		res |= syscall.PROT_READ
		if !payload {
			res |= syscall.PROT_GPU_READ
		}
	}
	if (flags & elf.PF_W) != 0 {
		res |= syscall.PROT_WRITE
		if !payload {
			res |= syscall.PROT_GPU_WRITE
		}
	}
	return
}

func (ldr *ElfLoader) mapElfMemory() error {
	// we don't need to worry about cleaning up the target process memory on failure
	// because the process will be killed anyway

	textSize, err := ldr.getTextSize()
	if err != nil {
		log.Println(err)
		return err
	}

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

	phdrs := ldr.elf.phdrs

	for i := range phdrs {
		phdr := &phdrs[i]
		if !phdr.Loadable() {
			continue
		}
		addr, err := ldr.toVirtualAddress(uintptr(phdrs[i].Paddr))
		if err != nil {
			log.Println(err)
			return err
		}

		size := pageAlign(uint(phdrs[i].Memsz))
		prot := toMmapProt(&phdrs[i], ldr.payload)
		var fd int
		var flags uint32
		if i == ldr.elf.textIndex {
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
			return fmt.Errorf("Tracer.Mmap did not give the requested address requested %#08x received %#08x", addr, res)
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
	return ldr.elf.getString(i)
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
		return errors.New("load_libraries Tracer.Mmap")
	}

	defer ldr.tracer.Munmap(uintptr(mem), _PAGE_LENGTH)

	dyn := ldr.elf.dyntab

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
	name := ldr.getString(int(ldr.elf.symtab[rel.Symbol()].Name))
	libsym := ldr.resolver.LookupSymbol(name)
	if libsym == 0 {
		return 0, fmt.Errorf("failed to find library symbol %s", name)
	}
	return libsym, nil
}

func (ldr *ElfLoader) processPltRelocations() error {
	if ldr.elf.plttab == nil {
		return nil
	}

	for i := range ldr.elf.plttab {
		plt := &ldr.elf.plttab[i]
		if plt.Type() != elf.R_X86_64_JMP_SLOT {
			sym := &ldr.elf.symtab[plt.Symbol()]
			name := ldr.getString(int(sym.Name))
			return fmt.Errorf("unexpected relocation type %s for symbol %s\n", plt.Type().String(), name)
		}

		libsym, err := ldr.getSymbolAddress(plt)
		if err != nil {
			log.Println(err)
			return err
		}
		symaddr, err := ldr.faddr(int(plt.r_offset))
		if err != nil {
			log.Println(err)
			return err
		}
		*(*uintptr)(symaddr) = libsym
	}

	return nil
}

func (ldr *ElfLoader) processRelaRelocations() error {
	if ldr.elf.reltab == nil {
		return nil
	}

	for i := range ldr.elf.reltab {
		rel := &ldr.elf.reltab[i]
		switch rel.Type() {
		case elf.R_X86_64_64:
			// symbol + addend
			libsym, err := ldr.getSymbolAddress(rel)
			if err != nil {
				log.Println(err)
				return err
			}
			symaddr, err := ldr.faddr(int(rel.r_offset))
			if err != nil {
				log.Println(err)
				return err
			}
			*(*uintptr)(symaddr) = libsym + uintptr(rel.r_addend)

		case elf.R_X86_64_GLOB_DAT:
			// symbol
			libsym, err := ldr.getSymbolAddress(rel)
			if err != nil {
				log.Println(err)
				return err
			}
			symaddr, err := ldr.faddr(int(rel.r_offset))
			if err != nil {
				log.Println(err)
				return err
			}
			*(*uintptr)(symaddr) = libsym
		case elf.R_X86_64_RELATIVE:
			// imagebase + addend
			symaddr, err := ldr.faddr(int(rel.r_offset))
			if err != nil {
				log.Println(err)
				return err
			}
			vaddr, err := ldr.toVirtualAddress(uintptr(rel.r_addend))
			if err != nil {
				log.Println(err)
				return err
			}
			*(*uintptr)(symaddr) = vaddr
		case elf.R_X86_64_JMP_SLOT:
			// edge case where the dynamic relocation sections are merged
			libsym, err := ldr.getSymbolAddress(rel)
			if err != nil {
				log.Println(err)
				return err
			}
			symaddr, err := ldr.faddr(int(rel.r_offset))
			if err != nil {
				log.Println(err)
				return err
			}
			*(*uintptr)(symaddr) = libsym
		default:
			sym := &ldr.elf.symtab[rel.Symbol()]
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

	buf := [...]uint32{20, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 0, 0, 0}
	const bufSize = int(unsafe.Sizeof(buf))

	err = ldr.tracer.Setsockopt(
		int(files[0]),
		syscall.IPPROTO_IPV6,
		syscall.IPV6_2292PKTOPTIONS,
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
		// edge case where the elf doesn't use libkernel
		proc := ldr.getProc()
		lib := proc.GetLib(LIBKERNEL_HANDLE)
		dlsym = lib.GetAddress(DLSYM_NID)
		if dlsym == 0 {
			return 0, ErrNoDlSym
		}
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
	phdrs := ldr.elf.phdrs
	for i := range phdrs {
		phdr := &phdrs[i]
		if isLoadable(phdr) {
			vaddr, err := ldr.toVirtualAddress(uintptr(phdr.Paddr))
			if err != nil {
				log.Println(err)
				return err
			}
			offset, err := ldr.toFileOffset(int(phdr.Offset))
			if err != nil {
				log.Println(err)
				return err
			}
			_, err = UserlandCopyin(ldr.pid, vaddr, ldr.elf.data[offset:offset+int(phdr.Filesz)])
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
	entry := uintptr(ldr.elf.ehdr.Entry)
	rip, err := ldr.toVirtualAddress(entry)
	if err != nil {
		log.Println(err)
		return err
	}
	regs.Rip = int64(rip)
	err = ldr.tracer.SetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return err
	}

	// it will run on detatch
	return nil
}

func (ldr *ElfLoader) Run() error {
	log.Println("mapping elf memory")
	err := ldr.mapElfMemory()
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

func (ldr *ElfLoader) Close() (err error) {
	if ldr.tracer != nil {
		err = ldr.tracer.Detach()
		ldr.tracer = nil
	}
	return
}

func (info *ElfLoadInfo) Close() (err error) {
	if info.reader != nil {
		err = info.reader.Close()
		info.reader = nil
	}
	if info.tracer != nil {
		err = errors.Join(err, info.tracer.Detach())
		info.tracer = nil
	}
	return
}

func readElfData(r io.ReadCloser, res chan elfReadResult, wg *sync.WaitGroup) {
	defer wg.Done()
	defer r.Close()

	var result elfReadResult

	defer func() {
		res <- result
		close(res)
	}()

	_, ok := r.(*os.File)
	if ok {
		data, err := io.ReadAll(r)
		result.buf = data
		result.err = err
		return
	}

	buf := ByteBuilder{}

	buf.Grow(int(ELF_HEADER_SIZE))

	// TODO read elf
	// need to do this the hard way because people are stupid and may not close the
	// connection after sending all the data
	n, err := buf.ReadFrom(r)
	if n != int64(ELF_HEADER_SIZE) {
		if err == nil {
			err = fmt.Errorf("only read %v out of %v bytes", n, ELF_HEADER_SIZE)
		}
		log.Println(err)
		result.err = err
		return
	}

	result.err = checkElf(buf.Bytes())
	if result.err != nil {
		log.Println(result.err)
		return
	}

	ehdr := *(*Elf64_Ehdr)(unsafe.Pointer(&(buf.Bytes()[0])))
	if ehdr.Phoff > Elf64_Off(ELF_HEADER_SIZE) {
		m := int(ehdr.Phoff - Elf64_Off(ELF_HEADER_SIZE))
		n, err = buf.ReadFrom(r)
		if n != int64(m) {
			if err == nil {
				err = fmt.Errorf("only read %v out of %v bytes", n, m)
			}
			log.Println(err)
			result.err = err
			return
		}
	}

	m := int(ELF_PROGRAM_HEADER_SIZE * uintptr(ehdr.Phnum))
	buf.Grow(int(m))
	n, err = buf.ReadFrom(r)
	if n != int64(m) {
		if err == nil {
			err = fmt.Errorf("only read %v out of %v bytes", n, m)
		}
		log.Println(err)
		result.err = err
		return
	}

	phdrs := unsafe.Slice((*Elf64_Phdr)(unsafe.Pointer(&(buf.Bytes()[ehdr.Phoff]))), ehdr.Phnum)
	var end uint
	for i := range phdrs {
		phdr := &phdrs[i]
		phdrEnd := uint(phdr.Offset) + uint(phdr.Filesz)
		if phdrEnd > end {
			end = phdrEnd
		}
	}

	if ehdr.Shnum > 0 {

		if ehdr.Shoff > ehdr.Phoff {
			log.Println("reading section headers")
			m = int(ELF_SECTION_HEADER_SIZE * uintptr(ehdr.Shnum))
			buf.Grow(int(m))
			n, err = buf.ReadFrom(r)
			if n != int64(m) {
				if err == nil {
					err = fmt.Errorf("only read %v out of %v bytes", n, m)
				}
				log.Println(err)
				result.err = err
				return
			}
		}

		shdrs := unsafe.Slice((*elf.Section64)(unsafe.Pointer(&(buf.Bytes()[ehdr.Shoff]))), ehdr.Shnum)
		for i := range shdrs {
			shdr := &shdrs[i]
			shdrEnd := uint(shdr.Off) + uint(shdr.Size)
			if shdrEnd > end {
				end = shdrEnd
			}
		}
	}

	m = int(int(end) - len(buf.Bytes()))
	buf.Grow(int(m))

	n, err = buf.ReadFrom(r)
	if n != int64(m) {
		if err == nil {
			err = fmt.Errorf("only read %v out of %v bytes", n, m)
		}
		log.Println(err)
		result.err = err
		return
	}

	result.buf = buf.Bytes()
}

func (info *ElfLoadInfo) LoadElf(hen *HenV) error {
	out := make(chan elfReadResult)

	hen.wg.Add(1)
	go readElfData(info.reader, out, &hen.wg)

	defer func() {
		if info.tracer != nil {
			info.tracer.Kill(false)
		}
		if info.pidChannel != nil && info.pid != -1 {
			hen.monitoredPids <- info.pid
		}
	}()

	// readElfData takes ownership
	info.reader = nil

	if info.tracer == nil {
		if info.pidChannel != nil {
			info.pid = <-info.pidChannel
		}
		tracer, err := NewTracer(info.pid)
		if err != nil {
			log.Println(err)
			return err
		}
		info.tracer = tracer
	}

	data := <-out
	if data.err != nil {
		log.Println(data.err)
		return data.err
	}

	if data.buf == nil {
		log.Println("No elf data")
	}

	proc := GetProc(info.pid)
	if proc == 0 {
		return ErrProcNotFound
	}

	proc.Jailbreak(info.payload)

	ldr, err := NewElfLoader(info.pid, info.tracer, data.buf, info.payload)
	if err != nil {
		log.Println(err)
		return err
	}

	// the elf loader now has ownership of the tracer
	info.tracer = nil

	defer ldr.Close()

	return ldr.Run()
}
