package henv

import "sync"

type KUcred uintptr

const (
	_UCRED_AUTHID_OFFSET  = 0x58
	_UCRED_UID_OFFSET     = 0x04
	_UCRED_RUID_OFFSET    = 0x08
	_UCRED_SVUID_OFFSET   = 0x0C
	_UCRED_NGROUPS_OFFSET = 0x10
	_UCRED_RGID_OFFSET    = 0x14
	_UCRED_SCECAPS_OFFSET = 0x60
)

var (
	currentAuthIdMtx *sync.Mutex
	_currentUcred    KUcred
)

func (u KUcred) RunWithAuthId(authid uint64, callback func()) {
	currentAuthIdMtx.Lock()
	defer currentAuthIdMtx.Unlock()
	addr := uintptr(u) + _UCRED_AUTHID_OFFSET
	orig := kread64(addr)
	kwrite64(addr, authid)
	defer kwrite64(addr, orig)
	callback()
}

func (u KUcred) GetAuthId() uint64 {
	return kread64(uintptr(u) + _UCRED_AUTHID_OFFSET)
}

func (u KUcred) SetAuthId(authid uint64) {
	kwrite64(uintptr(u)+_UCRED_AUTHID_OFFSET, authid)
}

func (u KUcred) SwapAuthId(authid uint64) uint64 {
	res := u.GetAuthId()
	u.SetAuthId(authid)
	return res
}

func (u KUcred) GetUid() uint32 {
	return kread32(uintptr(u) + _UCRED_UID_OFFSET)
}

func (u KUcred) GetRuid() uint32 {
	return kread32(uintptr(u) + _UCRED_RUID_OFFSET)
}

func (u KUcred) GetSvuid() uint32 {
	return kread32(uintptr(u) + _UCRED_SVUID_OFFSET)
}

func (u KUcred) GetNgroups() uint32 {
	return kread32(uintptr(u) + _UCRED_NGROUPS_OFFSET)
}

func (u KUcred) GetRgid() uint32 {
	return kread32(uintptr(u) + _UCRED_RGID_OFFSET)
}

func (u KUcred) SetUid(value uint32) {
	kwrite32(uintptr(u)+_UCRED_UID_OFFSET, value)
}

func (u KUcred) SetRuid(value uint32) {
	kwrite32(uintptr(u)+_UCRED_RUID_OFFSET, value)
}

func (u KUcred) SetSvuid(value uint32) {
	kwrite32(uintptr(u)+_UCRED_SVUID_OFFSET, value)
}

func (u KUcred) SetNgroups(value uint32) {
	kwrite32(uintptr(u)+_UCRED_NGROUPS_OFFSET, value)
}

func (u KUcred) SetRgid(value uint32) {
	kwrite32(uintptr(u)+_UCRED_RGID_OFFSET, value)
}

func (u KUcred) GetSceCaps() [2]uint64 {
	return [2]uint64{kread64(uintptr(u) + _UCRED_SCECAPS_OFFSET), kread64(uintptr(u) + _UCRED_SCECAPS_OFFSET + 8)}
}

func (u KUcred) SetSceCaps(v1 uint64, v2 uint64) {
	kwrite64(uintptr(u)+_UCRED_SCECAPS_OFFSET, v1)
	kwrite64(uintptr(u)+_UCRED_SCECAPS_OFFSET+8, v2)
}

func GetCurrentUcred() KUcred {
	return _currentUcred
}

func GetCurrentAuthId() uint64 {
	return GetCurrentUcred().GetAuthId()
}

func SetCurrentAuthId(value uint64) {
	GetCurrentUcred().SetAuthId(value)
}

func RunWithCurrentAuthId(authid uint64, callback func()) {
	GetCurrentUcred().RunWithAuthId(authid, callback)
}
