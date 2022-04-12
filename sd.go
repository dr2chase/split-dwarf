// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/dr2chase/split-dwarf/macho"
	"io/ioutil"
	"os"
	"strings"
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

// sd inputexe [ outputdwarf ]
func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Printf(`
Usage: %s inputexe [ outputdwarf ]
Reads the executable inputexe, extracts debugging into outputdwarf.
If outputdwarf is not specified, the path 
      inputexe.dSYM/Contents/Resources/DWARF/inputexe
is used instead.
`, os.Args[0])
		return
	}

	// Read input, find DWARF, be sure it looks right
	inexe := os.Args[1]
	exef, err := os.Open(inexe)
	if err != nil {
		fail("Could not open %s, error=%v", inexe, err)
	}
	exem, err := macho.NewFile(exef)
	if err != nil {
		fail("(internal) Couldn't create macho, err=%v", err)
	}
	// Postpone dealing with output till input is known-good

	cmdOffset := unsafe.Sizeof(exem.FileHeader)
	is64bit := exem.Magic == macho.Magic64
	if is64bit {
		// mach_header_64 has one extra uint32.
		cmdOffset += unsafe.Sizeof(exem.Magic)
	}

	// describe(&exem.FileTOC)

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

	//if uuid == nil {
	//	note("%s has no uuid", inexe)
	//}

	// Ensure a given load is not nil
	nonnilC := func(l macho.Load, s string) {
		if l == nil {
			fail("input file %s lacks load command %s", inexe, s)
		}
	}

	// Find a segment by name and ensure it is not nil
	nonnilS := func(s string) *macho.Segment {
		l := exem.Segment(s)
		if l == nil {
			fail("input file %s lacks segment %s", inexe, s)
		}
		return l
	}

	newtoc := exem.FileTOC.DerivedCopy(macho.MhDsym, 0)

	symtab := exem.Symtab
	dysymtab := exem.Dysymtab // Not appearing in output, but necessary to construct output
	nonnilC(symtab, "symtab")
	nonnilC(dysymtab, "dysymtab")
	text := nonnilS("__TEXT")
	data := nonnilS("__DATA")
	linkedit := nonnilS("__LINKEDIT")
	pagezero := nonnilS("__PAGEZERO")

	newtext := text.CopyZeroed()
	newdata := data.CopyZeroed()
	newsymtab := symtab.Copy()

	// Linkedit segment contain symbols and strings;
	// Symtab refers to offsets into linkedit.
	// This next bit initializes newsymtab and sets up data structures for the linkedit segment
	linkeditsyms := []macho.Nlist64{}
	linkeditstrings := []string{}

	// Linkedit will begin at the second page, i.e., offset is one page from beginning
	// Symbols come first
	linkeditsymbase := uint32(1) << pageAlign

	// Strings come second, offset by the number of symbols times their size.
	// Only those symbols from dysymtab.defsym are written into the debugging information.
	linkeditstringbase := linkeditsymbase + exem.FileTOC.SymbolSize()*dysymtab.Nextdefsym

	// The first two bytes of the strings are reserved for space, null (' ', \000)
	linkeditstringcur := uint32(2)

	newsymtab.Syms = newsymtab.Syms[:0]
	newsymtab.Symoff = linkeditsymbase
	newsymtab.Stroff = linkeditstringbase
	newsymtab.Nsyms = dysymtab.Nextdefsym
	for i := uint32(0); i < dysymtab.Nextdefsym; i++ {
		ii := i + dysymtab.Iextdefsym
		oldsym := symtab.Syms[ii]
		// fmt.Printf("Extdef %d = %#v\n", i, oldsym)
		newsymtab.Syms = append(newsymtab.Syms, oldsym)

		linkeditsyms = append(linkeditsyms, macho.Nlist64{Name: uint32(linkeditstringcur),
			Type: oldsym.Type, Sect: oldsym.Sect, Desc: oldsym.Desc, Value: oldsym.Value})
		linkeditstringcur += uint32(len(oldsym.Name)) + 1
		linkeditstrings = append(linkeditstrings, oldsym.Name)
	}
	newsymtab.Strsize = linkeditstringcur

	if uuid != nil {
		newtoc.AddLoad(uuid)
	}

	// For the specified segment (assumed to be in exem) make a copy of its
	// sections with appropriate fields zeroed out, and append them to the
	// currently-last segment in newtoc.
	copyZOdSections := func(g *macho.Segment) {
		for i := g.Firstsect; i < g.Firstsect+g.Nsect; i++ {
			s := exem.Sections[i].Copy()
			s.Offset = 0
			s.Reloff = 0
			s.Nreloc = 0
			newtoc.AddSection(s)
		}
	}

	newtoc.AddLoad(newsymtab)
	newtoc.AddSegment(pagezero)
	newtoc.AddSegment(newtext)
	copyZOdSections(text)
	newtoc.AddSegment(newdata)
	copyZOdSections(data)

	newlinkedit := linkedit.Copy()
	newlinkedit.Offset = uint64(linkeditsymbase)
	newlinkedit.Filesz = uint64(linkeditstringcur)
	newlinkedit.Addr = macho.RoundUp(newdata.Addr+newdata.Memsz, 1<<pageAlign)
	newlinkedit.Memsz = macho.RoundUp(newlinkedit.Filesz, 1<<pageAlign)
	// The rest should copy over fine.
	newtoc.AddSegment(newlinkedit)

	dwarf := nonnilS("__DWARF")
	newdwarf := dwarf.CopyZeroed()
	newdwarf.Offset = macho.RoundUp(newlinkedit.Offset+newlinkedit.Filesz, 1<<pageAlign)
	newdwarf.Filesz = dwarf.UncompressedSize(&exem.FileTOC, 1)
	newdwarf.Addr = newlinkedit.Addr + newlinkedit.Memsz
	newdwarf.Memsz = macho.RoundUp(newdwarf.Filesz, 1<<pageAlign)

	newtoc.AddSegment(newdwarf)

	offset := uint32(newdwarf.Offset)

	for i := dwarf.Firstsect; i < dwarf.Firstsect+dwarf.Nsect; i++ {
		o := exem.Sections[i]
		s := o.Copy()
		s.Offset = offset
		us := o.UncompressedSize()
		if s.Size < us {
			s.Size = uint64(us)
			s.Align = 0 // This is apparently true for debugging sections; not sure if it generalizes.
		}
		offset += uint32(us)
		if strings.HasPrefix(s.Name, "__z") {
			s.Name = s.Name[0:2] + s.Name[3:]
		}
		s.Reloff = 0
		s.Nreloc = 0
		newtoc.AddSection(s)
	}

	//note("New table of contents:")
	//describe(newtoc)

	buffer := make([]byte, newtoc.FileSize())

	// Write segments/sections.
	// Only dwarf and linkedit contain anything interesting.
	// (1) Linkedit segment
	offset = uint32(newlinkedit.Offset)
	for i := range linkeditsyms {
		if is64bit {
			offset += linkeditsyms[i].Put64(buffer[offset:], newtoc.ByteOrder)
		} else {
			offset += linkeditsyms[i].Put32(buffer[offset:], newtoc.ByteOrder)
		}
	}

	buffer[linkeditstringbase] = ' '
	buffer[linkeditstringbase+1] = 0
	offset = linkeditstringbase + 2
	for _, str := range linkeditstrings {
		for i := 0; i < len(str); i++ {
			buffer[offset] = str[i]
			offset++
		}
		buffer[offset] = 0
		offset++
	}

	// (2) DWARF segment
	ioff := newdwarf.Firstsect - dwarf.Firstsect
	for i := dwarf.Firstsect; i < dwarf.Firstsect+dwarf.Nsect; i++ {
		s := exem.Sections[i]
		j := i + ioff
		s.PutUncompressedData(buffer[newtoc.Sections[j].Offset:])
	}

	// Because "text" overlaps the header and the loads, write them afterwards, just in case.
	// Write header.
	newtoc.Put(buffer)

	outdwarf := inexe + ".dSYM/Contents/Resources/DWARF"
	if len(os.Args) > 2 {
		outdwarf = os.Args[2]
	} else {
		err := os.MkdirAll(outdwarf, 0755)
		if err != nil {
			fail("Could not create directory for debugging symbols %s, error=%v", outdwarf, err)
		}
		outdwarf += "/" + inexe
	}
	err = ioutil.WriteFile(outdwarf, buffer, 0755)
	if err != nil {
		fail("Could not create output dwarf/dsym file %s, error=%v\n", outdwarf, err)
	}
}

func describe(exem *macho.FileTOC) {
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
	if exem.Cmdsz != exem.LoadSize() {
		fail("recorded command size %d does not equal computed command size %d", exem.Cmdsz, exem.LoadSize())
	} else {
		note("recorded command size %d, computed command size %d", exem.Cmdsz, exem.LoadSize())
	}
	note("File size is %d", exem.FileSize())
}
