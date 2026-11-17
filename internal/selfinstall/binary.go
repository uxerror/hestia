package selfinstall

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
)

// ValidateServerBinary checks that b is a static linux/amd64 ELF executable
// (what runs on a fresh Debian container or server, CGO_ENABLED=0). It never
// executes anything.
func ValidateServerBinary(b []byte) error {
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return errors.New("это не исполняемый файл ELF")
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_X86_64 ||
		(f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX) {
		return fmt.Errorf("бинарник не для linux/amd64 (%s, %s)", f.Class, f.Machine)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return errors.New("это не исполняемый файл ELF")
	}
	dynamic := f.Section(".interp") != nil
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			dynamic = true
		}
	}
	if libs, _ := f.ImportedLibraries(); len(libs) > 0 {
		dynamic = true
	}
	if dynamic {
		return errors.New("бинарник слинкован динамически и не подойдёт для сервера: нужна сборка с CGO_ENABLED=0 (make server)")
	}
	return nil
}

// PayloadBinary returns the server binary embedded into a desktop build.
func PayloadBinary() ([]byte, error) {
	if b, ok := embeddedBinary(); ok {
		return b, nil
	}
	return nil, errNoBinary
}
