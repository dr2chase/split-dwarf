// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package macho implements access to Mach-O object files.
package macho

// High level access to low level data structures.

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"
)

type FileTOC struct {
	FileHeader
	ByteOrder binary.ByteOrder
	Loads     []Load
	Sections  []*Section
}

// DerivedCopy returns a modified copy of the TOC, with empty loads and sections,
// and with the specified header type and flags.
func (t *FileTOC) DerivedCopy(Type HdrType, Flags HdrFlags) *FileTOC {
	h := t.FileHeader
	h.Ncmd, h.Cmdsz, h.Type, h.Flags = 0, 0, Type, Flags

	return &FileTOC{FileHeader: h, ByteOrder: t.ByteOrder}
}

// TOCSize returns the size in bytes of the object file representation
// of the header and Load Commands (including Segments and Sections, but
// not their contents) at the beginning of a Mach-O file.  This typically
// overlaps the text segment in the object file.
func (t *FileTOC) TOCSize() uint64 {
	return t.HdrSize() + t.LoadSize()
}

func (t *FileTOC) LoadAlign() uint64 {
	if t.Magic == Magic64 {
		return 8
	}
	return 4
}

func (t *FileTOC) HdrSize() uint64 {
	switch t.Magic {
	case Magic32:
		return fileHeaderSize32
	case Magic64:
		return fileHeaderSize64
	case MagicFat:
		panic("MagicFat not handled yet")
	default:
		panic(fmt.Sprintf("Unexpected magic number 0x%x, expected Mach-O object file", t.Magic))
	}
}

// LoadSize returns the size of all the load commands in a file's table-of contents
// (but not their associated data, e.g., sections and symbol tables)
func (t *FileTOC) LoadSize() uint64 {
	cmdsz := uint64(0)
	for _, l := range t.Loads {
		s := l.LoadSize(t)
		cmdsz += s
	}
	return cmdsz
}

// FileSize returns the size in bytes of the header, load commands, and the
// in-file contents of all the segments and sections included in those
// load commands, accounting for their offsets within the file.
func (t *FileTOC) FileSize() uint64 {
	sz := uint64(t.LoadSize()) // ought to be contained in text segment, but just in case.
	for _, l := range t.Loads {
		if s, ok := l.(*Segment); ok {
			if m := s.Offset + s.Filesz; m > sz {
				sz = m
			}
		}
	}
	return sz
}

// TODO WIP

// CopyOC creates an empty copy of a file's table of contents.
func (f *File) CopyOC() *FileTOC {
	nt := &FileTOC{FileHeader: f.FileHeader, ByteOrder: f.ByteOrder}
	return nt
}

// UncompressedSize returns the size of the segment with its sections uncompressed, ignoring
// its offset within the file.  The returned size is rounded up to the power of two in align.
func (s *Segment) UncompressedSize(t *FileTOC, align uint64) uint64 {
	sz := uint64(0)
	for j := uint32(0); j < s.Nsect; j++ {
		c := t.Sections[j+s.Firstsect]
		sz += c.UncompressedSize()
	}
	return (sz + align - 1) & uint64(-int64(align))
}

func (s *Section) UncompressedSize() uint64 {
	if !strings.HasPrefix(s.Name, "__z") {
		return s.Size
	}
	b := make([]byte, 12)
	n, err := s.sr.ReadAt(b, 0)
	if err != nil {
		panic("Malformed object file")
	}
	if n != len(b) {
		return s.Size
	}
	if string(b[:4]) == "ZLIB" {
		return 12 + binary.BigEndian.Uint64(b[4:12])
	}
	return s.Size
}

// A File represents an open Mach-O file.
type File struct {
	FileTOC

	Symtab   *Symtab
	Dysymtab *Dysymtab

	closer io.Closer
}

// compress, uncompress, copy, remove
const (
	RESIZE_REMOVE = iota
	RESIZE_COPY
	RESIZE_UNCOMPRESS
	// RESIZE_COMPRESS
)

type move struct {
	from, to uint64
}

// A Load represents any Mach-O load command.
type Load interface {
	String() string
	Command() LoadCmd
	LoadSize(*FileTOC) uint64 // Need the TOC for alignment, sigh.

	// original_segment.ResizeFileData(copy Load, how int, align uint64) uint64, state // adjust file data; may be wrong in the immediate []byte data ; return new size.

	// original.AdjustFileOffsets(copy Load, moves []move) // with updated offsets, correct in copy
	// command LC_DYLD_INFO_ONLY contains offsets into __LINKEDIT
	// e.g., from "otool -l a.out"
	//
	// 	Load command 3
	//       cmd LC_SEGMENT_64
	//   cmdsize 72
	//   segname __LINKEDIT
	//    vmaddr 0x0000000100002000
	//    vmsize 0x0000000000001000
	//   fileoff 8192
	//  filesize 520
	//   maxprot 0x00000007
	//  initprot 0x00000001
	//    nsects 0
	//     flags 0x0
	// Load command 4
	//             cmd LC_DYLD_INFO_ONLY
	//         cmdsize 48
	//      rebase_off 8192
	//     rebase_size 8
	//        bind_off 8200
	//       bind_size 24
	//   weak_bind_off 0
	//  weak_bind_size 0
	//   lazy_bind_off 8224
	//  lazy_bind_size 16
	//      export_off 8240
	//     export_size 48

	// original_segment.CopyFileData(state interface{}, where []byte) // with a destination allocated

	// copy.CopyCommand(where []byte) // copy updated commands into place.
}

// LoadBytes is the uninterpreted bytes of a Mach-O load command.
type LoadBytes []byte

func (b LoadBytes) String() string {
	s := "["
	for i, a := range b {
		if i > 0 {
			s += " "
			if len(b) > 48 && i >= 16 {
				s += fmt.Sprintf("... (%d bytes)", len(b))
				break
			}
		}
		s += fmt.Sprintf("%x", a)
	}
	s += "]"
	return s
}

func (b LoadBytes) Raw() []byte                { return b }
func (b LoadBytes) Copy() LoadBytes            { return LoadBytes(append([]byte{}, b...)) }
func (b LoadBytes) LoadSize(t *FileTOC) uint64 { return uint64(len(b)) }

// LoadCmdBytes is a command-tagged sequence of bytes.
// This is used for Load Commands that are not (yet)
// interesting to us, and to common up this behavior for
// all those that are.
type LoadCmdBytes struct {
	LoadCmd
	LoadBytes
}

func (s LoadCmdBytes) String() string {
	return s.LoadCmd.String() + ": " + s.LoadBytes.String()
}
func (s LoadCmdBytes) Copy() LoadCmdBytes {
	return LoadCmdBytes{LoadCmd: s.LoadCmd, LoadBytes: s.LoadBytes.Copy()}
}

// A SegmentHeader is the header for a Mach-O 32-bit or 64-bit load segment command.
type SegmentHeader struct {
	LoadCmd
	Len       uint32
	Name      string // 16 characters or fewer
	Addr      uint64 // memory address
	Memsz     uint64 // memory size
	Offset    uint64 // file offset
	Filesz    uint64 // number of bytes starting at that file offset
	Maxprot   uint32
	Prot      uint32
	Nsect     uint32
	Flag      SegFlags
	Firstsect uint32
}

// A Segment represents a Mach-O 32-bit or 64-bit load segment command.
type Segment struct {
	SegmentHeader

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

func (s *SegmentHeader) String() string {
	return fmt.Sprintf(
		"Seg %s, len=0x%x, addr=0x%x, memsz=0x%x, offset=0x%x, filesz=0x%x, maxprot=0x%x, prot=0x%x, nsect=%d, flag=0x%x, firstsect=%d",
		s.Name, s.Len, s.Addr, s.Memsz, s.Offset, s.Filesz, s.Maxprot, s.Prot, s.Nsect, s.Flag, s.Firstsect)
}

func (s *Segment) String() string {
	return fmt.Sprintf(
		"Seg %s, len=0x%x, addr=0x%x, memsz=0x%x, offset=0x%x, filesz=0x%x, maxprot=0x%x, prot=0x%x, nsect=%d, flag=0x%x, firstsect=%d",
		s.Name, s.Len, s.Addr, s.Memsz, s.Offset, s.Filesz, s.Maxprot, s.Prot, s.Nsect, s.Flag, s.Firstsect)
}

// Data reads and returns the contents of the segment.
func (s *Segment) Data() ([]byte, error) {
	dat := make([]byte, s.sr.Size())
	n, err := s.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

func (s *Segment) Copy() *Segment {
	return &Segment{SegmentHeader: s.SegmentHeader}
}

func (s *Segment) LoadSize(t *FileTOC) uint64 {
	if s.Command() == LoadCmdSegment64 {
		return uint64(unsafe.Sizeof(Segment64{})) + uint64(s.Nsect)*uint64(unsafe.Sizeof(Section64{}))
	}
	return uint64(unsafe.Sizeof(Segment32{})) + uint64(s.Nsect)*uint64(unsafe.Sizeof(Section32{}))
}

// Open returns a new ReadSeeker reading the segment.
func (s *Segment) Open() io.ReadSeeker { return io.NewSectionReader(s.sr, 0, 1<<63-1) }

type SectionHeader struct {
	Name      string
	Seg       string
	Addr      uint64
	Size      uint64
	Offset    uint32
	Align     uint32
	Reloff    uint32
	Nreloc    uint32
	Flags     SecFlags
	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32 // only present if original was 64-bit
}

// A Reloc represents a Mach-O relocation.
type Reloc struct {
	Addr  uint32
	Value uint32
	// when Scattered == false && Extern == true, Value is the symbol number.
	// when Scattered == false && Extern == false, Value is the section number.
	// when Scattered == true, Value is the value that this reloc refers to.
	Type      uint8
	Len       uint8 // 0=byte, 1=word, 2=long, 3=quad
	Pcrel     bool
	Extern    bool // valid if Scattered == false
	Scattered bool
}

type Section struct {
	SectionHeader
	Relocs []Reloc

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

// Data reads and returns the contents of the Mach-O section.
func (s *Section) Data() ([]byte, error) {
	dat := make([]byte, s.sr.Size())
	n, err := s.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

func (s *Section) Copy() *Section {
	return &Section{SectionHeader: s.SectionHeader}
}

// Open returns a new ReadSeeker reading the Mach-O section.
func (s *Section) Open() io.ReadSeeker { return io.NewSectionReader(s.sr, 0, 1<<63-1) }

// A Dylib represents a Mach-O load dynamic library command.
type Dylib struct {
	DylibCmd
	Name           string
	Time           uint32
	CurrentVersion uint32
	CompatVersion  uint32
}

func (s *Dylib) String() string { return "Dylib " + s.Name }
func (s *Dylib) Copy() *Dylib {
	r := *s
	return &r
}
func (s *Dylib) LoadSize(t *FileTOC) uint64 {
	return roundup(uint64(unsafe.Sizeof(DylibCmd{}))+uint64(len(s.Name)), t.LoadAlign())
}

type Dylinker struct {
	DylinkerCmd // shared by 3 commands, need the LoadCmd
	Name        string
}

func (s *Dylinker) String() string { return s.DylinkerCmd.LoadCmd.String() + " " + s.Name }
func (s *Dylinker) Copy() *Dylinker {
	return &Dylinker{DylinkerCmd: s.DylinkerCmd, Name: s.Name}
}
func (s *Dylinker) LoadSize(t *FileTOC) uint64 {
	return roundup(uint64(unsafe.Sizeof(DylinkerCmd{}))+uint64(len(s.Name)), t.LoadAlign())
}

// A Symtab represents a Mach-O symbol table command.
type Symtab struct {
	SymtabCmd
	Syms []Symbol
}

func (s *Symtab) String() string { return fmt.Sprintf("Symtab %#v", s.SymtabCmd) }
func (s *Symtab) Copy() *Symtab {
	return &Symtab{SymtabCmd: s.SymtabCmd, Syms: append([]Symbol{}, s.Syms...)}
}
func (s *Symtab) LoadSize(t *FileTOC) uint64 {
	return uint64(unsafe.Sizeof(SymtabCmd{}))
}

type LinkEditData struct {
	LinkEditDataCmd
}

func (s *LinkEditData) String() string { return "LinkEditData " + s.LoadCmd.String() }
func (s *LinkEditData) Copy() *LinkEditData {
	return &LinkEditData{LinkEditDataCmd: s.LinkEditDataCmd}
}
func (s *LinkEditData) LoadSize(t *FileTOC) uint64 {
	return uint64(unsafe.Sizeof(LinkEditDataCmd{}))
}

type DyldInfo struct {
	DyldInfoCmd
}

func (s *DyldInfo) String() string { return "DyldInfo " + s.LoadCmd.String() }
func (s *DyldInfo) Copy() *DyldInfo {
	return &DyldInfo{DyldInfoCmd: s.DyldInfoCmd}
}
func (s *DyldInfo) LoadSize(t *FileTOC) uint64 {
	return uint64(unsafe.Sizeof(DyldInfoCmd{}))
}

type EncryptionInfo struct {
	EncryptionInfoCmd
}

func (s *EncryptionInfo) String() string { return "EncryptionInfo " + s.LoadCmd.String() }
func (s *EncryptionInfo) Copy() *EncryptionInfo {
	return &EncryptionInfo{EncryptionInfoCmd: s.EncryptionInfoCmd}
}
func (s *EncryptionInfo) LoadSize(t *FileTOC) uint64 {
	return uint64(unsafe.Sizeof(EncryptionInfoCmd{}))
}

// A Dysymtab represents a Mach-O dynamic symbol table command.
type Dysymtab struct {
	DysymtabCmd
	IndirectSyms []uint32 // indices into Symtab.Syms
}

func (s *Dysymtab) String() string { return fmt.Sprintf("Dysymtab %#v", s.DysymtabCmd) }
func (s *Dysymtab) Copy() *Dysymtab {
	return &Dysymtab{DysymtabCmd: s.DysymtabCmd, IndirectSyms: append([]uint32{}, s.IndirectSyms...)}
}
func (s *Dysymtab) LoadSize(t *FileTOC) uint64 {
	return uint64(unsafe.Sizeof(DysymtabCmd{}))
}

// A Rpath represents a Mach-O rpath command.
type Rpath struct {
	Path string
}

func (s *Rpath) String() string   { return "Rpath " + s.Path }
func (s *Rpath) Command() LoadCmd { return LoadCmdRpath }
func (s *Rpath) Copy() *Rpath {
	return &Rpath{Path: s.Path}
}
func (s *Rpath) LoadSize(t *FileTOC) uint64 {
	return roundup(uint64(unsafe.Sizeof(RpathCmd{}))+uint64(len(s.Path)), t.LoadAlign())
}

// A Symbol is a Mach-O 32-bit or 64-bit symbol table entry.
type Symbol struct {
	Name  string
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint64
}

/*
 * Mach-O reader
 */

// FormatError is returned by some operations if the data does
// not have the correct format for an object file.
type FormatError struct {
	off int64
	msg string
	val interface{}
}

func (e *FormatError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v'", e.val)
	}
	msg += fmt.Sprintf(" in record at byte %#x", e.off)
	return msg
}

// Open opens the named file using os.Open and prepares it for use as a Mach-O binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

// Close closes the File.
// If the File was created using NewFile directly instead of Open,
// Close has no effect.
func (f *File) Close() error {
	var err error
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return err
}

type fileHeader struct {
	Magic  uint32
	Cpu    uint32
	SubCpu uint32
	Type   uint32
	Ncmd   uint32 // number of load commands
	Cmdsz  uint32 // size of all the load commands
	Flags  uint32
}

// NewFile creates a new File for accessing a Mach-O binary in an underlying reader.
// The Mach-O binary is expected to start at position 0 in the ReaderAt.
func NewFile(r io.ReaderAt) (*File, error) {
	f := new(File)
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	// Read and decode Mach magic to determine byte order, size.
	// Magic32 and Magic64 differ only in the bottom bit.
	var ident [4]byte
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian.Uint32(ident[0:])
	le := binary.LittleEndian.Uint32(ident[0:])
	switch Magic32 &^ 1 {
	case be &^ 1:
		f.ByteOrder = binary.BigEndian
		f.Magic = be
	case le &^ 1:
		f.ByteOrder = binary.LittleEndian
		f.Magic = le
	default:
		return nil, &FormatError{0, "invalid magic number", nil}
	}

	// Read entire file header.
	if err := binary.Read(sr, f.ByteOrder, &f.FileHeader); err != nil {
		return nil, err
	}

	// Then load commands.
	offset := int64(fileHeaderSize32)
	if f.Magic == Magic64 {
		offset = fileHeaderSize64
	}
	dat := make([]byte, f.Cmdsz)
	if _, err := r.ReadAt(dat, offset); err != nil {
		return nil, err
	}
	f.Loads = make([]Load, f.Ncmd)
	bo := f.ByteOrder
	for i := range f.Loads {
		// Each load command begins with uint32 command and length.
		if len(dat) < 8 {
			return nil, &FormatError{offset, "command block too small", nil}
		}
		cmd, siz := LoadCmd(bo.Uint32(dat[0:4])), bo.Uint32(dat[4:8])
		if siz < 8 || siz > uint32(len(dat)) {
			return nil, &FormatError{offset, "invalid command block size", nil}
		}
		var cmddat []byte
		cmddat, dat = dat[0:siz], dat[siz:]
		offset += int64(siz)
		var s *Segment
		switch cmd {
		default:
			f.Loads[i] = LoadCmdBytes{LoadCmd(cmd), LoadBytes(cmddat)}

		case LoadCmdRpath:
			var hdr RpathCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(Rpath)
			if hdr.Path >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid path in rpath command", hdr.Path}
			}
			l.Path = cstring(cmddat[hdr.Path:])
			f.Loads[i] = l

		case LoadCmdLoadDylinker, LoadCmdIdDylinker, LoadCmdDyldEnv:
			var hdr DylinkerCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(Dylinker)
			if hdr.Name >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dynamic linker command", hdr.Name}
			}
			l.Name = cstring(cmddat[hdr.Name:])
			l.DylinkerCmd = hdr
			f.Loads[i] = l

		case LoadCmdDylib:
			var hdr DylibCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(Dylib)
			if hdr.Name >= uint32(len(cmddat)) {
				return nil, &FormatError{offset, "invalid name in dynamic library command", hdr.Name}
			}
			l.Name = cstring(cmddat[hdr.Name:])
			l.Time = hdr.Time
			l.CurrentVersion = hdr.CurrentVersion
			l.CompatVersion = hdr.CompatVersion
			f.Loads[i] = l

		case LoadCmdSymtab:
			var hdr SymtabCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			strtab := make([]byte, hdr.Strsize)
			if _, err := r.ReadAt(strtab, int64(hdr.Stroff)); err != nil {
				return nil, err
			}
			var symsz int
			if f.Magic == Magic64 {
				symsz = 16
			} else {
				symsz = 12
			}
			symdat := make([]byte, int(hdr.Nsyms)*symsz)
			if _, err := r.ReadAt(symdat, int64(hdr.Symoff)); err != nil {
				return nil, err
			}
			st, err := f.parseSymtab(symdat, strtab, cmddat, &hdr, offset)
			st.SymtabCmd = hdr
			if err != nil {
				return nil, err
			}
			f.Loads[i] = st
			f.Symtab = st

		case LoadCmdDysymtab:
			var hdr DysymtabCmd
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			dat := make([]byte, hdr.Nindirectsyms*4)
			if _, err := r.ReadAt(dat, int64(hdr.Indirectsymoff)); err != nil {
				return nil, err
			}
			x := make([]uint32, hdr.Nindirectsyms)
			if err := binary.Read(bytes.NewReader(dat), bo, x); err != nil {
				return nil, err
			}
			st := new(Dysymtab)
			st.DysymtabCmd = hdr
			st.IndirectSyms = x
			f.Loads[i] = st
			f.Dysymtab = st

		case LoadCmdSegment:
			var seg32 Segment32
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg32); err != nil {
				return nil, err
			}
			s = new(Segment)
			s.LoadCmd = cmd
			s.Len = siz
			s.Name = cstring(seg32.Name[0:])
			s.Addr = uint64(seg32.Addr)
			s.Memsz = uint64(seg32.Memsz)
			s.Offset = uint64(seg32.Offset)
			s.Filesz = uint64(seg32.Filesz)
			s.Maxprot = seg32.Maxprot
			s.Prot = seg32.Prot
			s.Nsect = seg32.Nsect
			s.Flag = seg32.Flag
			s.Firstsect = uint32(len(f.Sections))
			f.Loads[i] = s
			for i := 0; i < int(s.Nsect); i++ {
				var sh32 Section32
				if err := binary.Read(b, bo, &sh32); err != nil {
					return nil, err
				}
				sh := new(Section)
				sh.Name = cstring(sh32.Name[0:])
				sh.Seg = cstring(sh32.Seg[0:])
				sh.Addr = uint64(sh32.Addr)
				sh.Size = uint64(sh32.Size)
				sh.Offset = sh32.Offset
				sh.Align = sh32.Align
				sh.Reloff = sh32.Reloff
				sh.Nreloc = sh32.Nreloc
				sh.Flags = sh32.Flags
				sh.Reserved1 = sh32.Reserve1
				sh.Reserved2 = sh32.Reserve2
				if err := f.pushSection(sh, r); err != nil {
					return nil, err
				}
			}

		case LoadCmdSegment64:
			var seg64 Segment64
			b := bytes.NewReader(cmddat)
			if err := binary.Read(b, bo, &seg64); err != nil {
				return nil, err
			}
			s = new(Segment)
			s.LoadCmd = cmd
			s.Len = siz
			s.Name = cstring(seg64.Name[0:])
			s.Addr = seg64.Addr
			s.Memsz = seg64.Memsz
			s.Offset = seg64.Offset
			s.Filesz = seg64.Filesz
			s.Maxprot = seg64.Maxprot
			s.Prot = seg64.Prot
			s.Nsect = seg64.Nsect
			s.Flag = seg64.Flag
			s.Firstsect = uint32(len(f.Sections))
			f.Loads[i] = s
			for i := 0; i < int(s.Nsect); i++ {
				var sh64 Section64
				if err := binary.Read(b, bo, &sh64); err != nil {
					return nil, err
				}
				sh := new(Section)
				sh.Name = cstring(sh64.Name[0:])
				sh.Seg = cstring(sh64.Seg[0:])
				sh.Addr = sh64.Addr
				sh.Size = sh64.Size
				sh.Offset = sh64.Offset
				sh.Align = sh64.Align
				sh.Reloff = sh64.Reloff
				sh.Nreloc = sh64.Nreloc
				sh.Flags = sh64.Flags
				sh.Reserved1 = sh64.Reserve1
				sh.Reserved2 = sh64.Reserve2
				sh.Reserved3 = sh64.Reserve3
				if err := f.pushSection(sh, r); err != nil {
					return nil, err
				}
			}

		case LoadCmdCodeSignature, LoadCmdSegmentSplitInfo, LoadCmdFunctionStarts,
			LoadCmdDataInCode, LoadCmdDylibCodeSignDrs:
			var hdr LinkEditDataCmd
			b := bytes.NewReader(cmddat)

			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(LinkEditData)

			l.LinkEditDataCmd = hdr
			f.Loads[i] = l

		case LoadCmdEncryptionInfo, LoadCmdEncryptionInfo64:
			var hdr EncryptionInfoCmd
			b := bytes.NewReader(cmddat)

			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(EncryptionInfo)

			l.EncryptionInfoCmd = hdr
			f.Loads[i] = l

		case LoadCmdDyldInfo, LoadCmdDyldInfoOnly:
			var hdr DyldInfoCmd
			b := bytes.NewReader(cmddat)

			if err := binary.Read(b, bo, &hdr); err != nil {
				return nil, err
			}
			l := new(DyldInfo)

			l.DyldInfoCmd = hdr
			f.Loads[i] = l
		}
		if s != nil {
			s.sr = io.NewSectionReader(r, int64(s.Offset), int64(s.Filesz))
			s.ReaderAt = s.sr
		}
		if f.Loads[i].LoadSize(&f.FileTOC) != uint64(siz) {
			fmt.Printf("Oops, actual size was %d, calculated was %d, load was %s\n", siz, f.Loads[i].LoadSize(&f.FileTOC), f.Loads[i].String())
			panic("oops")
		}
	}
	return f, nil
}

func (f *File) parseSymtab(symdat, strtab, cmddat []byte, hdr *SymtabCmd, offset int64) (*Symtab, error) {
	bo := f.ByteOrder
	symtab := make([]Symbol, hdr.Nsyms)
	b := bytes.NewReader(symdat)
	for i := range symtab {
		var n Nlist64
		if f.Magic == Magic64 {
			if err := binary.Read(b, bo, &n); err != nil {
				return nil, err
			}
		} else {
			var n32 Nlist32
			if err := binary.Read(b, bo, &n32); err != nil {
				return nil, err
			}
			n.Name = n32.Name
			n.Type = n32.Type
			n.Sect = n32.Sect
			n.Desc = n32.Desc
			n.Value = uint64(n32.Value)
		}
		sym := &symtab[i]
		if n.Name >= uint32(len(strtab)) {
			return nil, &FormatError{offset, "invalid name in symbol table", n.Name}
		}
		sym.Name = cstring(strtab[n.Name:])
		sym.Type = n.Type
		sym.Sect = n.Sect
		sym.Desc = n.Desc
		sym.Value = n.Value
	}
	st := new(Symtab)
	st.Syms = symtab
	return st, nil
}

type relocInfo struct {
	Addr   uint32
	Symnum uint32
}

func (f *File) pushSection(sh *Section, r io.ReaderAt) error {
	f.Sections = append(f.Sections, sh)
	sh.sr = io.NewSectionReader(r, int64(sh.Offset), int64(sh.Size))
	sh.ReaderAt = sh.sr

	if sh.Nreloc > 0 {
		reldat := make([]byte, int(sh.Nreloc)*8)
		if _, err := r.ReadAt(reldat, int64(sh.Reloff)); err != nil {
			return err
		}
		b := bytes.NewReader(reldat)

		bo := f.ByteOrder

		sh.Relocs = make([]Reloc, sh.Nreloc)
		for i := range sh.Relocs {
			rel := &sh.Relocs[i]

			var ri relocInfo
			if err := binary.Read(b, bo, &ri); err != nil {
				return err
			}

			if ri.Addr&(1<<31) != 0 { // scattered
				rel.Addr = ri.Addr & (1<<24 - 1)
				rel.Type = uint8((ri.Addr >> 24) & (1<<4 - 1))
				rel.Len = uint8((ri.Addr >> 28) & (1<<2 - 1))
				rel.Pcrel = ri.Addr&(1<<30) != 0
				rel.Value = ri.Symnum
				rel.Scattered = true
			} else {
				switch bo {
				case binary.LittleEndian:
					rel.Addr = ri.Addr
					rel.Value = ri.Symnum & (1<<24 - 1)
					rel.Pcrel = ri.Symnum&(1<<24) != 0
					rel.Len = uint8((ri.Symnum >> 25) & (1<<2 - 1))
					rel.Extern = ri.Symnum&(1<<27) != 0
					rel.Type = uint8((ri.Symnum >> 28) & (1<<4 - 1))
				case binary.BigEndian:
					rel.Addr = ri.Addr
					rel.Value = ri.Symnum >> 8
					rel.Pcrel = ri.Symnum&(1<<7) != 0
					rel.Len = uint8((ri.Symnum >> 5) & (1<<2 - 1))
					rel.Extern = ri.Symnum&(1<<4) != 0
					rel.Type = uint8(ri.Symnum & (1<<4 - 1))
				default:
					panic("unreachable")
				}
			}
		}
	}

	return nil
}

func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		i = len(b)
	}
	return string(b[0:i])
}

// Segment returns the first Segment with the given name, or nil if no such segment exists.
func (f *File) Segment(name string) *Segment {
	for _, l := range f.Loads {
		if s, ok := l.(*Segment); ok && s.Name == name {
			return s
		}
	}
	return nil
}

// Section returns the first section with the given name, or nil if no such
// section exists.
func (f *File) Section(name string) *Section {
	for _, s := range f.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// DWARF returns the DWARF debug information for the Mach-O file.
func (f *File) DWARF() (*dwarf.Data, error) {
	dwarfSuffix := func(s *Section) string {
		switch {
		case strings.HasPrefix(s.Name, "__debug_"):
			return s.Name[8:]
		case strings.HasPrefix(s.Name, "__zdebug_"):
			return s.Name[9:]
		default:
			return ""
		}

	}
	sectionData := func(s *Section) ([]byte, error) {
		b, err := s.Data()
		if err != nil && uint64(len(b)) < s.Size {
			return nil, err
		}

		if len(b) >= 12 && string(b[:4]) == "ZLIB" {
			dlen := binary.BigEndian.Uint64(b[4:12])
			dbuf := make([]byte, dlen)
			r, err := zlib.NewReader(bytes.NewBuffer(b[12:]))
			if err != nil {
				return nil, err
			}
			if _, err := io.ReadFull(r, dbuf); err != nil {
				return nil, err
			}
			if err := r.Close(); err != nil {
				return nil, err
			}
			b = dbuf
		}
		return b, nil
	}

	// There are many other DWARF sections, but these
	// are the ones the debug/dwarf package uses.
	// Don't bother loading others.
	var dat = map[string][]byte{"abbrev": nil, "info": nil, "str": nil, "line": nil, "ranges": nil}
	for _, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix == "" {
			continue
		}
		if _, ok := dat[suffix]; !ok {
			continue
		}
		b, err := sectionData(s)
		if err != nil {
			return nil, err
		}
		dat[suffix] = b
	}

	d, err := dwarf.New(dat["abbrev"], nil, nil, dat["info"], dat["line"], nil, dat["ranges"], dat["str"])
	if err != nil {
		return nil, err
	}

	// Look for DWARF4 .debug_types sections.
	for i, s := range f.Sections {
		suffix := dwarfSuffix(s)
		if suffix != "types" {
			continue
		}

		b, err := sectionData(s)
		if err != nil {
			return nil, err
		}

		err = d.AddTypes(fmt.Sprintf("types-%d", i), b)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}

// ImportedSymbols returns the names of all symbols
// referred to by the binary f that are expected to be
// satisfied by other libraries at dynamic load time.
func (f *File) ImportedSymbols() ([]string, error) {
	if f.Dysymtab == nil || f.Symtab == nil {
		return nil, &FormatError{0, "missing symbol table", nil}
	}

	st := f.Symtab
	dt := f.Dysymtab
	var all []string
	for _, s := range st.Syms[dt.Iundefsym : dt.Iundefsym+dt.Nundefsym] {
		all = append(all, s.Name)
	}
	return all, nil
}

// ImportedLibraries returns the paths of all libraries
// referred to by the binary f that are expected to be
// linked with the binary at dynamic link time.
func (f *File) ImportedLibraries() ([]string, error) {
	var all []string
	for _, l := range f.Loads {
		if lib, ok := l.(*Dylib); ok {
			all = append(all, lib.Name)
		}
	}
	return all, nil
}

func roundup(x, align uint64) uint64 {
	return uint64((x + align - 1) & -align)
}
