package henv

import (
	"encoding/binary"
	"log"
	"slices"
	"unsafe"
)

const _INTERNAL_LIBRARY_METADATA_OFFSET = 0x28
const _EXPORT_MASK = 0x30

type InternalLibraryMetadata struct {
	symtab     uintptr
	symtabSize uintptr
	strtab     uintptr
	strtabSize uintptr
}

type NidKeyValue struct {
	low   int64
	hi    int32
	index int32
}

type NidMap []NidKeyValue

type LibraryInfo struct {
	imagebase uintptr
	symtab    []Elf64_Sym
	strtab    []byte
}

type SymbolLookupTable struct {
	info    LibraryInfo
	symbols NidMap
}

type Resolver struct {
	libs []SymbolLookupTable
}

func NewResolver() Resolver {
	return Resolver{
		libs: make([]SymbolLookupTable, 3),
	}
}

func NewNid(nid []byte, index int32) NidKeyValue {
	data := nid[:11]
	data = append(data, 0)
	return NidKeyValue{
		low:   int64(binary.BigEndian.Uint64(data)),
		hi:    int32(binary.BigEndian.Uint32(data[:8])),
		index: index,
	}
}

func compareNid(lhs, rhs NidKeyValue) int {
	i := int(lhs.low) - int(rhs.low)
	if i != 0 {
		return i
	}
	return int(lhs.hi) - int(rhs.hi)
}

func (tbl NidMap) binarySearch(key NidKeyValue) int {
	var lo int
	hi := len(tbl) - 1

	for lo <= hi {
		m := (lo + hi) >> 1
		n := compareNid(tbl[m], key)

		if n == 0 {
			return m
		}

		if n < 0 {
			lo = m + 1
		} else {
			hi = m - 1
		}
	}
	return -(lo + 1)
}

func (nid *NidKeyValue) String() string {
	ptr := (*byte)(unsafe.Pointer(nid))
	return string(unsafe.Slice(ptr, 11))
}

func (tbl *NidMap) insertNid(sym Elf64_Sym, strtab []byte, i int32) {
	name := strtab[sym.Name : sym.Name+12]
	nid := NewNid(name, int32(i))
	index := tbl.binarySearch(nid)
	if index >= 0 {
		// this is actually ok
		return
	}
	*tbl = slices.Insert(*tbl, -(index + 1), nid)
}

func (tbl *SymbolLookupTable) fillLookupTable(symtab []Elf64_Sym, strtab []byte) {
	for i := 1; i < len(symtab); i++ {
		sym := symtab[i]
		if sym.Exported() {
			tbl.symbols.insertNid(sym, strtab, int32(i))
		}
	}
}

func (r *Resolver) AddLibraryMetaData(imagebase uintptr, meta SharedLibMetaData) error {
	var info InternalLibraryMetadata
	const size = unsafe.Sizeof(info)
	_, err := KernelCopyoutUnsafe(uintptr(meta)+_INTERNAL_LIBRARY_METADATA_OFFSET, unsafe.Pointer(&info), int(size))
	if err != nil {
		log.Println(err)
		return err
	}

	symtabLength := info.symtabSize / unsafe.Sizeof(Elf64_Sym{})
	symtab := make([]Elf64_Sym, int(symtabLength))
	_, err = KernelCopyoutUnsafe(info.symtab, unsafe.Pointer(&symtab[0]), int(info.symtabSize))
	if err != nil {
		log.Println(err)
		return err
	}

	strtab := make([]byte, int(info.strtabSize))
	_, err = KernelCopyout(info.strtab, strtab)
	if err != nil {
		log.Println(err)
		return err
	}

	r.libs = append(r.libs, SymbolLookupTable{
		info: LibraryInfo{
			imagebase: imagebase,
			symtab:    symtab,
			strtab:    strtab,
		},
		symbols: NidMap(make([]NidKeyValue, 0, symtabLength)),
	})

	lib := &r.libs[len(r.libs)-1]

	lib.fillLookupTable(symtab, strtab)

	lib.symbols = slices.Clip(lib.symbols)

	return nil
}

func isExported(sym *Elf64_Sym) bool {
	return (sym.Info & _EXPORT_MASK) != 0
}

func (r *Resolver) LookupSymbol(sym string) uintptr {
	nid := NewNid([]byte(GetNid(sym)), 0)
	for i := range r.libs {
		lib := &r.libs[i]
		index := lib.symbols.binarySearch(nid)
		if index >= 0 {
			value := lib.symbols[index]
			symbol := &lib.info.symtab[value.index]
			if isExported(symbol) {
				return lib.info.imagebase + uintptr(symbol.Value)
			}
		}
	}
	return 0
}
