package main

const (
	LIBKERNEL_HANDLE             = 0x2001
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

func (lib SharedLib) GetImageBase() uintptr {
	return uintptr(kread64(lib + _SHARED_LIB_IMAGEBASE_OFFSET))
}

func (lib SharedLib) next() SharedLib {
	return SharedLib(kread64(lib))
}

func (lib SharedLib) Handle() int {
	return int(kread32(lib + _LIB_HANDLE_OFFSET))
}

func (obj SharedObject) GetLib(handle int) SharedLib {
	for lib := SharedLib(kread64(obj)); lib != 0; lib = lib.next() {
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
