package main

import (
	"log"
	"unsafe"
)

const (
	LIBKERNEL_HANDLE             = 0x2001
	LIBC_HANDLE                  = 2
	_SHARED_LIB_IMAGEBASE_OFFSET = 0x30
	_SHARED_LIB_METADATA_OFFSET  = 0x148
	_SECTION_TYPE_TEXT           = 1
	_SECTION_TYPE_XOTEXT         = 2
	_SECTION_TYPE_DATA           = 16
	_SECTIONS_ITERATOR_OFFSET    = 0x40
	_TYPE_OFFSET                 = 8
	_ADDRESS_OFFSET              = 8
	_LENGTH_OFFSET               = 16
	_ALLOCATION_ALIGNMENT        = 0x10
	_ALLOCATION_ALIGNMENT_MASK   = 0xf
	_LIB_HANDLE_OFFSET           = 0x28
	_LIB_PATH_OFFSET             = 0x8
	_METADATA_PLT_HELPER_OFFSET  = 0x28
	_NID_LENGTH                  = 11
)

type SharedObject uintptr
type SharedLib uintptr
type SharedLibMetaData uintptr

type RtldPltHelper struct {
	symtab      uintptr
	symtab_size uintptr
	strtab      uintptr
	strtab_size uintptr
	plttab      uintptr
	plttab_size uintptr
}

type RtldSectionIterator struct {
	sections     uintptr
	num_sections uint64
}

type RtldSection struct {
	sectionType uintptr
	start       uintptr
	length      uint64
}

func (lib SharedLib) GetImageBase() uintptr {
	return uintptr(kread64(uintptr(lib) + _SHARED_LIB_IMAGEBASE_OFFSET))
}

func (lib SharedLib) next() SharedLib {
	return SharedLib(kread64(uintptr(lib)))
}

func (lib SharedLib) Handle() int {
	return int(kread32(uintptr(lib) + _LIB_HANDLE_OFFSET))
}

func (lib SharedLib) GetMetaData() SharedLibMetaData {
	return SharedLibMetaData(kread64(uintptr(lib) + _SHARED_LIB_METADATA_OFFSET))
}

func (lib SharedLib) GetAddress(nid Nid) uintptr {
	meta := lib.GetMetaData()
	if meta == 0 {
		log.Println("failed to get metadata")
		return 0
	}
	imagebase := lib.GetImageBase()
	if imagebase == 0 {
		log.Println("failed to get imagebase")
		return 0
	}
	helper := meta.GetPltHelper()
	if helper == nil {
		log.Println("failed to get plt helper")
		return 0
	}
	return getSymbolAddress(helper, imagebase, nid)
}

func (meta SharedLibMetaData) GetPltHelper() *RtldPltHelper {
	res := RtldPltHelper{}
	const size = unsafe.Sizeof(res)
	_, err := KernelCopyoutUnsafe(uintptr(meta)+_METADATA_PLT_HELPER_OFFSET, unsafe.Pointer(&res), int(size))
	if err != nil {
		log.Println(err)
		return nil
	}
	return &res
}

func getSymbolAddress(helper *RtldPltHelper, imagebase uintptr, nid Nid) uintptr {
	const symsize = unsafe.Sizeof(Elf64_Sym{})
	numSymbls := int(helper.symtab_size / symsize)
	symtab := make([]Elf64_Sym, numSymbls)

	KernelCopyoutUnsafe(helper.symtab, unsafe.Pointer(&symtab[0]), int(helper.symtab_size))

	strtab := make([]byte, helper.strtab_size)

	KernelCopyout(helper.strtab, strtab)

	for i := 1; i < len(symtab); i++ {
		offset := symtab[i].Name
		sym := string(strtab[offset : offset+_NID_LENGTH])
		if sym == string(nid) {
			return imagebase + uintptr(symtab[i].Value)
		}
	}
	log.Printf("failed to get symbol address for %s", nid)
	return 0
}

func (obj SharedObject) GetLib(handle int) SharedLib {
	for lib := SharedLib(kread64(uintptr(obj))); lib != 0; lib = lib.next() {
		currentHandle := lib.Handle()
		if currentHandle == -1 {
			// read failed
			return 0
		}
		if currentHandle == handle {
			return lib
		}
	}
	return 0
}
