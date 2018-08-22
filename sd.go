// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	_ "bytes"
	// "compress/zlib"
	"./macho"
	_ "encoding/binary"
	// "flag"
	"fmt"
	// "io"
	"os"
	// "reflect"
	"unsafe"
)

const (
	pageAlign = 12 // 4096 = 1 << 12
)

func note(format string, why ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", why...)
}

func fail(format string, why ...interface{}) {
	note(format, why...)
	os.Exit(1)
}

type loadCmd struct {
	Cmd macho.LoadCmd
	Len uint32
}

// For 64-bit Mach-O, these appear in the __LINKEDIT section.
// It is not known whether these are used in 32-bit Mach-O;
// I was unable to find an official declaration for this type,
// and instead relied on the output of Mach-O browsers
// (e.g., https://github.com/gdbinit/MachOView )
type SymbolTableEntry struct {
	StringTableIndex uint32
	Type             uint8
	SectionIndex     uint8
	Description      uint16
	Value            uint64
}

// sd inputexe outputexe outputdwarf
func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Printf(`
Usage: %s inputexe outputdwarf [ outputexe ]
Reads the executable inputexe, extracts debugging into outputdwarf,
writes debugging-stripped (but linked via ___ section) outputexe.
`, os.Args[0])
		return
	}

	// Read input, find DWARF, be sure it looks right

	inexe := os.Args[1]
	outdwarf := os.Args[2]
	outexe := ""
	if len(os.Args) > 3 {
		outexe = os.Args[3]
	}

	exef, err := os.Open(inexe)
	if err != nil {
		fail("Could not open %s, error=%v", inexe, err)
	}

	exem, err := macho.NewFile(exef)
	if err != nil {
		fail("(internal) Couldn't create macho")
	}
	cmdOffset := unsafe.Sizeof(exem.FileHeader)
	is64bit := exem.Magic == macho.Magic64
	if is64bit {
		// mach_header_64 has one extra uint32.
		cmdOffset += unsafe.Sizeof(exem.Magic)
	}

	note("Type = %s, Flags=0x%x", exem.Type, uint32(exem.Flags))

	for i, l := range exem.Loads {
		if s, ok := l.(*macho.Segment); ok {
			fmt.Printf("Load %d is Segment %s, offset=0x%x, filesz=%d, addr=0x%x, memsz=%d, nsect=%d\n", i, s.Name,
				s.Offset, s.Filesz, s.Addr, s.Memsz, s.Nsect)
			for j := uint32(0); j < s.Nsect; j++ {
				c := exem.Sections[j+s.Firstsect]
				fmt.Printf("   Section %s, offset=0x%x, size=%d, addr=0x%x, flags=0x%x, nreloc=%d, res1=%d, res2=%d, res3=%d\n", c.Name, c.Offset, c.Size, c.Addr, c.Flags, c.Nreloc, c.Reserved1, c.Reserved2, c.Reserved3)
			}
		} else {
			fmt.Printf("Load %d is %v\n", i, l)
		}
	}

	// Offsets into __LINKEDIT:
	//
	// Command LC_SYMTAB =
	//  (1) number of symbols at file offset (within link edit section) of 16-byte symbol table entries
	// struct {
	//  StringTableIndex uint32
	//  Type, SectionIndex uint8
	//  Description uint16
	//  Value uint64
	// }
	//
	// (2) string table offset and size.  Strings are zero-byte terminated.  First must be " ".
	//
	// Command LC_DYSYMTAB = indices within symtab (above), except for IndSym
	//   IndSym Offset = file offset (within link edit section) of 4-byte indices within symtab.
	//
	// Section __TEXT.__symbol_stub1.
	//   Offset and size (Reserved2) locate and describe a table for thios section.
	//   Symbols beginning at IndirectSymIndex (Reserved1) (see LC_DYSYMTAB.IndSymOffset) refer to this table.
	//   (These table entries are PLTs, I think)
	//
	// Section __DATA.__nl_symbol_ptr.
	//   Reserved1 seems to be an index within the Indirect symbols (see LC_DYSYMTAB.IndSymOffset)
	//   Some of these symbols appear to be duplicates of other indirect symbols appearing early
	//
	// Section __DATA.__la_symbol_ptr.
	//   Reserved1 seems to be an index within the Indirect symbols (see LC_DYSYMTAB.IndSymOffset)
	//   Some of these symbols appear to be duplicates of other indirect symbols appearing early
	//

	if uint64(exem.Cmdsz) != exem.LoadSize() {
		fail("recorded command size %d does not equal computed command size %d", exem.Cmdsz, exem.LoadSize())
	} else {
		note("recorded command size %d, computed command size %d", exem.Cmdsz, exem.LoadSize())
	}
	note("File size is %d", exem.FileSize())

	// Create a File for the output dwarf.
	// Copy header, file type is MH_DSYM
	// Copy the relevant load commands

	// LoadCmdUuid
	// Symtab -- very abbreviated (Use DYSYMTAB Iextdefsym, Nextdefsym to identify these).
	// Segment __PAGEZERO
	// Segment __TEXT (zero the size, zero the offset of each section)
	// Segment __DATA (zero the size, zero the offset of each section)
	// Segment __LINKEDIT (contains the symbols and strings from Symtab)
	// Segment __DWARF (uncompressed)

	var uuid macho.Load
	for _, l := range exem.Loads {
		switch l.Command() {
		case macho.LcUuid:
			uuid = l
		}
	}

	if uuid == nil {
		note("%s has no uuid", inexe)
	}

	nonnilC := func(l macho.Load, s string) {
		if l == nil {
			fail("input file %s lacks load command %s", inexe, s)
		}
	}

	nonnilS := func(s string) *macho.Segment {
		l := exem.Segment(s)
		if l == nil {
			fail("input file %s lacks segment %s", inexe, s)
		}
		return l
	}

	symtab := exem.Symtab
	dysymtab := exem.Dysymtab // Not appearing in output, but necessary to construct output
	nonnilC(symtab, "symtab")
	nonnilC(dysymtab, "dysymtab")

	text := nonnilS("__TEXT")
	data := nonnilS("__DATA")
	linkedit := nonnilS("__LINKEDIT")
	dwarf := nonnilS("__DWARF")
	pagezero := nonnilS("__PAGEZERO")

	// Figure out the size
	// uuid + symtab + pagezero + text + data +
	// linkedit which is derived from dsymtab +
	// dwarf which is uncompressed
	newtext := text.Copy()
	newdata := data.Copy()
	newsymtab := symtab.Copy()

	for i := uint32(0); i < dysymtab.Nextdefsym; i++ {
		ii := i + dysymtab.Iextdefsym
		fmt.Printf("Extdef %d = %#v\n", i, symtab.Syms[ii])
	}

	if true { // TODO work in progress
		_ = newsymtab
		_ = newtext
		_ = newdata
		_ = linkedit
		_ = dwarf
		_ = pagezero
		return
	}

	// Create output files

	outdf, err := os.Create(outdwarf)
	if err != nil {
		fail("Could not create %s, error=%v\n", outdwarf, err)
	}
	outdf.Chmod(0755)

	if true { // TODO work in progress
		return
	}

	outf, err := os.Create(outexe)
	if err != nil {
		fail("Could not create %s, error=%v\n", outexe, err)
	}
	outf.Chmod(0755)

}

// addAndAlign adds x and y, and aligns that result (rounding up)
// to an a-aligned boundary.  a should be a power of two.
func addAndAlign(x, y, a uint64) uint64 {
	if a&(a-1) != 0 {
		panic("a is not a power of two")
	}
	z := x + y
	w := z & (a - 1)
	if w != 0 {
		z += (a - w)
	}
	return z
}
