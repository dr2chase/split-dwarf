// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Mach-O header data structures
// http://developer.apple.com/mac/library/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html

package macho

import "strconv"

// A FileHeader represents a Mach-O file header.
type FileHeader struct {
	Magic  uint32
	Cpu    Cpu
	SubCpu uint32
	Type   HdrType
	Ncmd   uint32 // number of load commands
	Cmdsz  uint32 // size of all the load commands
	Flags  HdrFlags
}

const (
	fileHeaderSize32 = 7 * 4
	fileHeaderSize64 = 8 * 4
)

const (
	Magic32  uint32 = 0xfeedface
	Magic64  uint32 = 0xfeedfacf
	MagicFat uint32 = 0xcafebabe
)

type HdrFlags uint32
type SegFlags uint32
type SecFlags uint32

// A HdrType is the Mach-O file type, e.g. an object file, executable, or dynamic library.
type HdrType uint32

const (
	TypeObj    HdrType = 1
	TypeExec   HdrType = 2
	TypeCore   HdrType = 4
	TypeDylib  HdrType = 6
	TypeBundle HdrType = 8
	TypeDsym   HdrType = 0xa
)

var typeStrings = []intName{
	{uint32(TypeObj), "Obj"},
	{uint32(TypeExec), "Exec"},
	{uint32(TypeDylib), "Dylib"},
	{uint32(TypeBundle), "Bundle"},
}

func (t HdrType) String() string   { return stringName(uint32(t), typeStrings, false) }
func (t HdrType) GoString() string { return stringName(uint32(t), typeStrings, true) }

// A Cpu is a Mach-O cpu type.
type Cpu uint32

const cpuArch64 = 0x01000000

const (
	Cpu386   Cpu = 7
	CpuAmd64 Cpu = Cpu386 | cpuArch64
	CpuArm   Cpu = 12
	CpuArm64 Cpu = CpuArm | cpuArch64
	CpuPpc   Cpu = 18
	CpuPpc64 Cpu = CpuPpc | cpuArch64
)

var cpuStrings = []intName{
	{uint32(Cpu386), "Cpu386"},
	{uint32(CpuAmd64), "CpuAmd64"},
	{uint32(CpuArm), "CpuArm"},
	{uint32(CpuArm64), "CpuArm64"},
	{uint32(CpuPpc), "CpuPpc"},
	{uint32(CpuPpc64), "CpuPpc64"},
}

func (i Cpu) String() string   { return stringName(uint32(i), cpuStrings, false) }
func (i Cpu) GoString() string { return stringName(uint32(i), cpuStrings, true) }

// A LoadCmd is a Mach-O load command.
type LoadCmd uint32

func (c LoadCmd) Command() LoadCmd { return c }

const (
	// Note 3 and 8 are obsolete
	LoadCmdSegment          LoadCmd = 0x1
	LoadCmdSymtab           LoadCmd = 0x2
	LoadCmdThread           LoadCmd = 0x4
	LoadCmdUnixThread       LoadCmd = 0x5 // thread+stack
	LoadCmdDysymtab         LoadCmd = 0xb
	LoadCmdDylib            LoadCmd = 0xc // load dylib command
	LoadCmdIdDylib          LoadCmd = 0xd // dynamically linked shared lib ident
	LoadCmdLoadDylinker     LoadCmd = 0xe // load a dynamic linker
	LoadCmdIdDylinker       LoadCmd = 0xf // id dylinker command (not load dylinker command)
	LoadCmdSegment64        LoadCmd = 0x19
	LoadCmdUuid             LoadCmd = 0x1b
	LoadCmdCodeSignature    LoadCmd = 0x1d
	LoadCmdSegmentSplitInfo LoadCmd = 0x1e
	LoadCmdRpath            LoadCmd = 0x8000001c
	LoadCmdEncryptionInfo   LoadCmd = 0x21
	LoadCmdDyldInfo         LoadCmd = 0x22
	LoadCmdDyldInfoOnly     LoadCmd = 0x80000022
	LoadCmdMinOsx           LoadCmd = 0x24
	LoadCmdMinIos           LoadCmd = 0x25
	LoadCmdFunctionStarts   LoadCmd = 0x26
	LoadCmdDyldEnv          LoadCmd = 0x27
	LoadCmdMain             LoadCmd = 0x80000028 // replacement for UnixThread
	LoadCmdDataInCode       LoadCmd = 0x29       // There are non-instructions in text
	LoadCmdSourceVersion    LoadCmd = 0x2a       // Source version used to build binary
	LoadCmdDylibCodeSignDrs LoadCmd = 0x2b
	LoadCmdEncryptionInfo64 LoadCmd = 0x2c
	LoadCmdMinTvos          LoadCmd = 0x2f
	LoadCmdMinWatchos       LoadCmd = 0x30
)

var cmdStrings = []intName{
	{uint32(LoadCmdSegment), "LoadCmdSegment"},
	{uint32(LoadCmdThread), "LoadCmdThread"},
	{uint32(LoadCmdUnixThread), "LoadCmdUnixThread"},
	{uint32(LoadCmdDylib), "LoadCmdDylib"},
	{uint32(LoadCmdIdDylib), "LoadCmdIdDylib"},
	{uint32(LoadCmdLoadDylinker), "LoadCmdLoadDylinker"},
	{uint32(LoadCmdIdDylinker), "LoadCmdIdDylinker"},
	{uint32(LoadCmdSegment64), "LoadCmdSegment64"},
	{uint32(LoadCmdUuid), "LoadCmdUuid"},
	{uint32(LoadCmdRpath), "LoadCmdRpath"},
	{uint32(LoadCmdDyldEnv), "LoadCmdDyldEnv"},
	{uint32(LoadCmdMain), "LoadCmdMain"},
	{uint32(LoadCmdDataInCode), "LoadCmdDataInCode"},
	{uint32(LoadCmdSourceVersion), "LoadCmdSourceVersion"},
	{uint32(LoadCmdDyldInfo), "LoadCmdDyldInfo"},
	{uint32(LoadCmdDyldInfoOnly), "LoadCmdDyldInfoOnly"},
	{uint32(LoadCmdMinOsx), "LoadCmdMinOsx"},
	{uint32(LoadCmdFunctionStarts), "LoadCmdFunctionStarts"},
}

func (i LoadCmd) String() string   { return stringName(uint32(i), cmdStrings, false) }
func (i LoadCmd) GoString() string { return stringName(uint32(i), cmdStrings, true) }

type (
	// A Segment32 is a 32-bit Mach-O segment load command.
	Segment32 struct {
		LoadCmd
		Len     uint32
		Name    [16]byte
		Addr    uint32
		Memsz   uint32
		Offset  uint32
		Filesz  uint32
		Maxprot uint32
		Prot    uint32
		Nsect   uint32
		Flag    SegFlags
	}

	// A Segment64 is a 64-bit Mach-O segment load command.
	Segment64 struct {
		LoadCmd
		Len     uint32
		Name    [16]byte
		Addr    uint64
		Memsz   uint64
		Offset  uint64
		Filesz  uint64
		Maxprot uint32
		Prot    uint32
		Nsect   uint32
		Flag    SegFlags
	}

	// A SymtabCmd is a Mach-O symbol table command.
	SymtabCmd struct {
		LoadCmd
		Len     uint32
		Symoff  uint32
		Nsyms   uint32
		Stroff  uint32
		Strsize uint32
	}

	// A DysymtabCmd is a Mach-O dynamic symbol table command.
	DysymtabCmd struct {
		LoadCmd
		Len            uint32
		Ilocalsym      uint32
		Nlocalsym      uint32
		Iextdefsym     uint32
		Nextdefsym     uint32
		Iundefsym      uint32
		Nundefsym      uint32
		Tocoffset      uint32
		Ntoc           uint32
		Modtaboff      uint32
		Nmodtab        uint32
		Extrefsymoff   uint32
		Nextrefsyms    uint32
		Indirectsymoff uint32
		Nindirectsyms  uint32
		Extreloff      uint32
		Nextrel        uint32
		Locreloff      uint32
		Nlocrel        uint32
	}

	// A DylibCmd is a Mach-O load dynamic library command.
	DylibCmd struct {
		LoadCmd
		Len            uint32
		Name           uint32
		Time           uint32
		CurrentVersion uint32
		CompatVersion  uint32
	}

	// A DylinkerCmd is a Mach-O load dynamic linker or environment command.
	DylinkerCmd struct {
		LoadCmd
		Len  uint32
		Name uint32
	}

	// A RpathCmd is a Mach-O rpath command.
	RpathCmd struct {
		LoadCmd
		Len  uint32
		Path uint32
	}

	// A Thread is a Mach-O thread state command.
	Thread struct {
		LoadCmd
		Len  uint32
		Type uint32
		Data []uint32
	}

	// LC_DYLD_INFO, LC_DYLD_INFO_ONLY
	DyldInfoCmd struct {
		LoadCmd
		Len                      uint32
		RebaseOff, RebaseLen     uint32 // file offset and length; data contains segment indices
		BindOff, BindLen         uint32 // file offset and length; data contains segment indices
		WeakBindOff, WeakBindLen uint32 // file offset and length
		LazyBindOff, LazyBindLen uint32 // file offset and length
		ExportOff, ExportLen     uint32 // file offset and length
	}

	// LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO, LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS
	LinkEditDataCmd struct {
		LoadCmd
		Len              uint32
		DataOff, DataLen uint32 // file offset and length
	}

	// LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64
	EncryptionInfoCmd struct {
		LoadCmd
		Len                uint32
		CryptOff, CryptLen uint32 // file offset and length
		CryptId            uint32
	}

	// TODO Commands below not fully supported yet.

	EntryPointCmd struct {
		LoadCmd
		Len       uint32
		EntryOff  uint64 // file offset
		StackSize uint64 // if not zero, initial stack size
	}

	NoteCmd struct {
		LoadCmd
		Len            uint32
		Name           [16]byte
		Offset, Filesz uint64 // file offset and length
	}
)

const (
	FlagNoUndefs              HdrFlags = 0x1
	FlagIncrLink              HdrFlags = 0x2
	FlagDyldLink              HdrFlags = 0x4
	FlagBindAtLoad            HdrFlags = 0x8
	FlagPrebound              HdrFlags = 0x10
	FlagSplitSegs             HdrFlags = 0x20
	FlagLazyInit              HdrFlags = 0x40
	FlagTwoLevel              HdrFlags = 0x80
	FlagForceFlat             HdrFlags = 0x100
	FlagNoMultiDefs           HdrFlags = 0x200
	FlagNoFixPrebinding       HdrFlags = 0x400
	FlagPrebindable           HdrFlags = 0x800
	FlagAllModsBound          HdrFlags = 0x1000
	FlagSubsectionsViaSymbols HdrFlags = 0x2000
	FlagCanonical             HdrFlags = 0x4000
	FlagWeakDefines           HdrFlags = 0x8000
	FlagBindsToWeak           HdrFlags = 0x10000
	FlagAllowStackExecution   HdrFlags = 0x20000
	FlagRootSafe              HdrFlags = 0x40000
	FlagSetuidSafe            HdrFlags = 0x80000
	FlagNoReexportedDylibs    HdrFlags = 0x100000
	FlagPIE                   HdrFlags = 0x200000
	FlagDeadStrippableDylib   HdrFlags = 0x400000
	FlagHasTLVDescriptors     HdrFlags = 0x800000
	FlagNoHeapExecution       HdrFlags = 0x1000000
	FlagAppExtensionSafe      HdrFlags = 0x2000000
)

// A Section32 is a 32-bit Mach-O section header.
type Section32 struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint32
	Size     uint32
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    SecFlags
	Reserve1 uint32
	Reserve2 uint32
}

// A Section64 is a 64-bit Mach-O section header.
type Section64 struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint64
	Size     uint64
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    SecFlags
	Reserve1 uint32
	Reserve2 uint32
	Reserve3 uint32
}

// An Nlist32 is a Mach-O 32-bit symbol table entry.
type Nlist32 struct {
	Name  uint32
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint32
}

// An Nlist64 is a Mach-O 64-bit symbol table entry.
type Nlist64 struct {
	Name  uint32
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint64
}

// Regs386 is the Mach-O 386 register structure.
type Regs386 struct {
	AX    uint32
	BX    uint32
	CX    uint32
	DX    uint32
	DI    uint32
	SI    uint32
	BP    uint32
	SP    uint32
	SS    uint32
	FLAGS uint32
	IP    uint32
	CS    uint32
	DS    uint32
	ES    uint32
	FS    uint32
	GS    uint32
}

// RegsAMD64 is the Mach-O AMD64 register structure.
type RegsAMD64 struct {
	AX    uint64
	BX    uint64
	CX    uint64
	DX    uint64
	DI    uint64
	SI    uint64
	BP    uint64
	SP    uint64
	R8    uint64
	R9    uint64
	R10   uint64
	R11   uint64
	R12   uint64
	R13   uint64
	R14   uint64
	R15   uint64
	IP    uint64
	FLAGS uint64
	CS    uint64
	FS    uint64
	GS    uint64
}

type intName struct {
	i uint32
	s string
}

func stringName(i uint32, names []intName, goSyntax bool) string {
	for _, n := range names {
		if n.i == i {
			if goSyntax {
				return "macho." + n.s
			}
			return n.s
		}
	}
	return "0x" + strconv.FormatUint(uint64(i), 16)
}
