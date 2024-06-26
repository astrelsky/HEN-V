package henv

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
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
	ErrNoMalloc                   = errors.New("failed to resolve malloc")
	ErrProcessNotReady            = errors.New("elf_start process is not ready (FS is 0)")
	ErrNoSigaction                = errors.New("failed to resolve sigaction")
	ErrNoGetpid                   = errors.New("failed to resolve getpid")
	ErrNoElfData                  = errors.New("no elf data")
	ErrTracerMmap                 = errors.New("load_libraries Tracer.Mmap")
	ErrNullSock                   = errors.New("sock == 0")
	ErrNullMasterPcb              = errors.New("master pcb == 0")
	ErrNullMasterOutputOpts       = errors.New("master_inp6_outputopts == 0")
	ErrNullVictimPcb              = errors.New("victim pcb == 0")
	ErrNullVictimOutputOpts       = errors.New("victim_inp6_outputopts == 0")
	ErrBadKernelSockets           = errors.New("kernel sockets are invalid")
)

const (
	_STACK_ALIGN               = 0x10
	_PAGE_LENGTH               = 0x4000
	_MMAP_TEXT_FLAGS           = syscall.MAP_FIXED | syscall.MAP_SHARED
	_MMAP_DATA_FLAGS           = syscall.MAP_FIXED | syscall.MAP_ANONYMOUS | syscall.MAP_PRIVATE
	_PAYLOAD_ARGS_SIZE         = int(0x30)
	DLSYM_NID              Nid = "LwG8g3niqwA"
	MALLOC_NID             Nid = "gQX+4GDQjpM"
	_ELFLDR_MAX_GOROUTINES     = 6
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

func NewElfLoader(pid int, tracer *Tracer, data []byte, payload bool) (ElfLoader, error) {
	var err error
	if tracer == nil {
		tracer, err = NewTracer(pid)
		if err != nil {
			log.Println(err)
			return ElfLoader{}, err
		}
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
	if text.Vaddr == 0 {
		return ldr.imagebase + addr, nil
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
			log.Printf("addr: %#08x, size: %v\n", addr, size)
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
	id := syscall.GetInternalPrxId(lib)
	if id != 0 {
		res, err := ldr.tracer.Call(id_loader, id, 0, 0, 0, 0, 0)
		if err != nil || res != 0 {
			err = fmt.Errorf("failed to load lib %s id %#x err %#x", lib, id, res)
			log.Println(err)
			return 0, err
		}
		return GetModuleHandle(ldr.pid, lib), nil
	}
	clib, err := syscall.BytePtrFromString(lib)
	if err != nil {
		log.Println(err)
		return 0, err
	}
	_, err = UserlandCopyinUnsafe(ldr.pid, mem, unsafe.Pointer(clib), len(lib)+1)
	if err != nil {
		log.Println(err)
		return 0, err
	}

	res, err := ldr.tracer.Call(name_loader, mem, 0, 0, 0, 0, 0)
	if err != nil || int32(res) < 0 {
		err = fmt.Errorf("failed to load lib %s", lib)
		log.Println(err)
		return 0, err
	}
	return res, nil
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
		log.Println(ErrTracerMmap)
		return ErrTracerMmap
	}

	defer ldr.tracer.Munmap(uintptr(mem), _PAGE_LENGTH)

	dyn := ldr.elf.dyntab

	for ; dyn.Tag() != elf.DT_NULL; dyn = dyn.Next() {
		if dyn.Tag() != elf.DT_NEEDED {
			continue
		}

		var handle int

		lib := ldr.getString(dyn.Value())
		if strings.HasPrefix(lib, "libkernel") {
			handle = LIBKERNEL_HANDLE
		} else if strings.HasPrefix(lib, "libc.") || strings.HasPrefix(lib, "libSceLibcInternal") {
			handle = LIBC_HANDLE
		} else {
			lib, _ = strings.CutSuffix(lib, ".so")
			handle, err = ldr.loadLibrary(idLoader, nameLoader, uintptr(mem), lib)
			if err != nil {
				log.Println(err)
				return err
			}
		}

		if handle < 0 {
			return fmt.Errorf("failed to load library %s", lib)
		}

		err = ldr.addLibrary(handle)

		if err != nil && handle == LIBKERNEL_HANDLE {
			err = ldr.addLibrary(1)
		}

		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func (ldr *ElfLoader) getSymbolAddress(rel Elf64_Rela) (uintptr, error) {
	name := ldr.getString(int(ldr.elf.symtab[rel.Symbol()].Name))
	libsym := ldr.resolver.LookupSymbol(name)
	if libsym == 0 {
		return 0, fmt.Errorf("failed to find library symbol %s", name)
	}
	return libsym, nil
}

func (ldr *ElfLoader) processPltRelocation(plt Elf64_Rela) error {
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
	return nil
}

func (ldr *ElfLoader) processPltRelocations() error {
	if ldr.elf.plttab == nil {
		return nil
	}

	for i := range ldr.elf.plttab {
		plt := ldr.elf.plttab[i]
		if plt.Type() != elf.R_X86_64_JMP_SLOT {
			sym := &ldr.elf.symtab[plt.Symbol()]
			name := ldr.getString(int(sym.Name))
			return fmt.Errorf("unexpected relocation type %s for symbol %s", plt.Type().String(), name)
		}
		err := ldr.processPltRelocation(plt)
		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}

func (ldr *ElfLoader) processRelaRelocation(rel Elf64_Rela) error {
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
		return fmt.Errorf("unexpected relocation type %s for symbol %s", rel.Type().String(), name)
	}
	return nil
}

func (ldr *ElfLoader) processRelaRelocations() error {
	if ldr.elf.reltab == nil {
		return nil
	}

	for i := range ldr.elf.reltab {
		err := ldr.processRelaRelocation(ldr.elf.reltab[i])
		if err != nil {
			log.Println(err)
			return err
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
		log.Println(ErrNullSock)
		return ErrNullSock
	}
	Kwrite32(sock, 0x100)
	pcb := uintptr(Kread64(sock + 0x18))
	if pcb == 0 {
		log.Println(ErrNullMasterPcb)
		return ErrNullMasterPcb
	}
	master_inp6_outputopts := uintptr(Kread64(pcb + 0x120))
	if master_inp6_outputopts == 0 {
		log.Println(ErrNullMasterOutputOpts)
		return ErrNullMasterOutputOpts
	}
	sock = uintptr(newtbl.GetFileData(sockets[1]))
	Kwrite32(sock, 0x100)
	pcb = uintptr(Kread64(sock + 0x18))
	if pcb == 0 {
		log.Println(ErrNullVictimPcb)
		return ErrNullVictimPcb
	}
	victim_inp6_outputopts := Kread64(pcb + 0x120)
	if victim_inp6_outputopts == 0 {
		log.Println(ErrNullVictimOutputOpts)
		return ErrNullVictimOutputOpts
	}
	Kwrite64(master_inp6_outputopts+0x10, victim_inp6_outputopts+0x10)
	Kwrite32(master_inp6_outputopts+0xc0, 0x13370000)
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
		err = ErrBadKernelSockets
		log.Println(err)
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
	pipeaddr := uintptr(Kread64(newtbl.GetFile(int(files[2]))))

	var regs Reg
	err = ldr.tracer.GetRegisters(&regs)
	if err != nil {
		log.Println(err)
		return
	}

	malloc := ldr.resolver.LookupSymbol("malloc")
	if malloc == 0 {
		// edge case where the elf doesn't use libc
		proc := ldr.getProc()
		lib := proc.GetLib(LIBC_HANDLE)
		malloc = lib.GetAddress(MALLOC_NID)
		if malloc == 0 {
			err = ErrNoMalloc
			log.Println(err)
			return
		}
	}

	const fileSize = int(unsafe.Sizeof(files))

	ptr, err := ldr.tracer.Call(malloc, 68, 0, 0, 0, 0, 0)
	if err != nil {
		log.Println(err)
		return
	}
	resPtr := int64(ptr)
	ptr += 4
	newFiles := int64(ptr)
	ptr += fileSize
	args := int64(ptr)

	_, err = UserlandCopyinUnsafe(ldr.pid, uintptr(newFiles), unsafe.Pointer(&files[0]), fileSize)
	if err != nil {
		log.Println(err)
		return
	}

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
		if lib == 0 {
			lib = proc.GetLib(1)
		}
		dlsym = lib.GetAddress(DLSYM_NID)
		if dlsym == 0 {
			err = ErrNoDlSym
			log.Println(err)
			return
		}
	}

	result := [6]uintptr{
		dlsym,
		uintptr(newFiles + 8),
		uintptr(newFiles),
		pipeaddr,
		GetKernelBase(),
		uintptr(resPtr),
	}

	UserlandCopyinUnsafe(ldr.pid, uintptr(args), unsafe.Pointer(&result[0]), _PAYLOAD_ARGS_SIZE)
	addr = uintptr(args)
	return
}

func (ldr *ElfLoader) load() error {
	phdrs := ldr.elf.phdrs
	for i := range phdrs {
		phdr := &phdrs[i]
		if isLoadable(phdr) {
			if phdr.Filesz == 0 {
				// bss
				continue
			}
			vaddr, err := ldr.toVirtualAddress(uintptr(phdr.Paddr))
			if err != nil {
				log.Println(err)
				return err
			}
			offset := int(phdr.Offset)
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
		// if tracer isn't nil then an error has occured
		errors.Join(err, info.tracer.Kill(false))
		errors.Join(err, info.tracer.Detach())
		info.tracer = nil
	}
	return
}

func readElfData(r io.ReadCloser) (data []byte, err error) {

	defer r.Close()

	_, ok := r.(*os.File)
	if ok {
		return io.ReadAll(r)
	}

	buf := ByteBuilder{}

	buf.Grow(int(ELF_HEADER_SIZE))

	n, err := buf.ReadFrom(r)
	if n != int64(ELF_HEADER_SIZE) {
		if err == nil {
			err = fmt.Errorf("only read %v out of %v bytes", n, ELF_HEADER_SIZE)
		}
		log.Println(err)
		return
	}

	err = checkElf(buf.Bytes())
	if err != nil {
		log.Println(err)
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
			off := int(ehdr.Shoff) - len(buf.Bytes())
			if off > 0 {
				m += off
			}
			log.Printf("growing %#x bytes\n", m)
			buf.Grow(int(m))
			log.Printf("read %#x bytes, reading %#x bytes\n", len(buf.Bytes()), m)
			n, err = buf.ReadFrom(r)
			if n != int64(m) {
				if err == nil {
					err = fmt.Errorf("only read %v out of %v bytes", n, m)
				}
				log.Println(err)
				return
			}
			if err != nil {
				log.Println(err)
				return
			}
		}

		shdrs := unsafe.Slice((*elf.Section64)(unsafe.Pointer(&(buf.Bytes()[ehdr.Shoff]))), ehdr.Shnum)
		for i := range shdrs {
			shdr := &shdrs[i]
			if elf.SectionType(shdr.Type) == elf.SHT_NOBITS {
				continue
			}
			shdrEnd := uint(shdr.Off) + uint(shdr.Size)
			if shdrEnd > end {
				end = shdrEnd
			}
		}
	}

	m = int(int(end) - len(buf.Bytes()))
	if m <= 0 {
		// section headers can be at the end of the file
		data = buf.Bytes()
		return
	}

	buf.Grow(int(m))

	log.Println("reading remaining elf data")

	n, err = buf.ReadFrom(r)
	if n != int64(m) {
		if err == nil {
			err = fmt.Errorf("only read %v out of %v bytes", n, m)
		}
		log.Println(err)
		return
	}

	data = buf.Bytes()

	return
}

func (info *ElfLoadInfo) LoadElf(hen *HenV) error {
	defer info.Close()

	if info.tracer == nil {
		tracer, err := NewTracer(info.pid)
		if err != nil {
			log.Println(err)
			info.reader.Close()
			return err
		}
		info.tracer = tracer
	}

	buf, err := readElfData(info.reader)

	// readElfData takes ownership
	info.reader = nil

	if err != nil {
		log.Println(err)
		return err
	}

	if buf == nil {
		log.Println(ErrNoElfData)
		return ErrNoElfData
	}

	proc := GetProc(info.pid)
	if proc == 0 {
		return ErrProcNotFound
	}

	proc.Jailbreak(info.payload >= 0)

	ldr, err := NewElfLoader(info.pid, info.tracer, buf, info.payload >= 0)
	if err != nil {
		log.Println(err)
		return err
	}

	// the elf loader now has ownership of the tracer
	info.tracer = nil

	defer ldr.Close()

	return ldr.Run()
}
