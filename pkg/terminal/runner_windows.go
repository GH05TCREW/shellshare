//go:build windows
// +build windows

package terminal

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const procThreadAttributePseudoConsole = 0x00020016

// Start runs the shell attached to a ConPTY for proper interactive behavior on Windows 10+.
func (r Runner) Start(ctx context.Context, outWriter io.Writer, localInput <-chan []byte, remoteInput <-chan []byte) error {
	// Create pipes for the ConPTY
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle:      1,
		SecurityDescriptor: nil,
	}

	var ptyInRead, ptyInWrite windows.Handle
	if err := windows.CreatePipe(&ptyInRead, &ptyInWrite, &sa, 0); err != nil {
		return err
	}
	defer windows.CloseHandle(ptyInRead)
	defer windows.CloseHandle(ptyInWrite)

	var ptyOutRead, ptyOutWrite windows.Handle
	if err := windows.CreatePipe(&ptyOutRead, &ptyOutWrite, &sa, 0); err != nil {
		return err
	}
	defer windows.CloseHandle(ptyOutRead)
	defer windows.CloseHandle(ptyOutWrite)

	hpc, err := createPseudoConsole(coord{X: 80, Y: 24}, ptyInRead, ptyOutWrite, 0)
	if err != nil {
		return fmt.Errorf("create pseudoconsole: %w", err)
	}
	defer closePseudoConsole(hpc)

	attrList, raw, err := newAttrList(hpc)
	if err != nil {
		return err
	}
	defer deleteProcThreadAttributeList(attrList)
	defer raw.Free()

	// Prepare STARTUPINFOEX with attached ConPTY
	si := new(windows.StartupInfoEx)
	si.ProcThreadAttributeList = attrList
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(*si))

	// Build the command line
	cmdLine := windows.StringToUTF16Ptr(strings.Join(append([]string{r.Command}, r.Args...), " "))

	var pi windows.ProcessInformation
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)

	if err := windows.CreateProcess(
		nil,
		cmdLine,
		nil,
		nil,
		false,
		flags,
		nil,
		nil,
		&si.StartupInfo,
		&pi,
	); err != nil {
		return fmt.Errorf("create process: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// Host-facing ends as *os.File
	outFile := os.NewFile(uintptr(ptyOutRead), "conpty-stdout")
	inFile := os.NewFile(uintptr(ptyInWrite), "conpty-stdin")
	defer outFile.Close()
	defer inFile.Close()

	// Stream process output to caller.
	go io.Copy(outWriter, outFile)

	// Feed local + remote input into the PTY.
	go func() {
		for {
			select {
			case data, ok := <-localInput:
				if !ok {
					return
				}
				if len(data) > 0 {
					_, _ = inFile.Write(data)
				}
			case data, ok := <-remoteInput:
				if !ok {
					return
				}
				if len(data) > 0 {
					_, _ = inFile.Write(data)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() {
		_, err := windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		if err != nil {
			waitCh <- err
			return
		}
		var code uint32
		_ = windows.GetExitCodeProcess(pi.Process, &code)
		if code != 0 {
			waitCh <- fmt.Errorf("process exited with code %d", code)
		} else {
			waitCh <- nil
		}
	}()

	select {
	case err := <-waitCh:
		return err
	case <-ctx.Done():
		_ = windows.TerminateProcess(pi.Process, 1)
		select {
		case err := <-waitCh:
			return err
		case <-time.After(2 * time.Second):
			return ctx.Err()
		}
	}
}

type coord struct {
	X int16
	Y int16
}

// createPseudoConsole wraps Kernel32 CreatePseudoConsole.
func createPseudoConsole(size coord, in, out windows.Handle, flags uint32) (windows.Handle, error) {
	var hpc windows.Handle
	r1, _, e1 := procCreatePseudoConsole.Call(
		uintptr(*(*uint32)(unsafe.Pointer(&size))),
		uintptr(in),
		uintptr(out),
		uintptr(flags),
		uintptr(unsafe.Pointer(&hpc)),
	)
	if r1 != 0 {
		if e1 != nil {
			return 0, e1
		}
		return 0, syscall.Errno(r1)
	}
	return hpc, nil
}

func closePseudoConsole(hpc windows.Handle) {
	procClosePseudoConsole.Call(uintptr(hpc))
}

var (
	modkernel32                          = windows.NewLazySystemDLL("kernel32.dll")
	procCreatePseudoConsole              = modkernel32.NewProc("CreatePseudoConsole")
	procClosePseudoConsole               = modkernel32.NewProc("ClosePseudoConsole")
	procInitializeProcThreadAttributeList = modkernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute        = modkernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList    = modkernel32.NewProc("DeleteProcThreadAttributeList")
)

// attrListMemory keeps the raw backing buffer alive for the attribute list.
type attrListMemory []byte

func (m *attrListMemory) Free() {
	if m != nil {
		*m = nil
	}
}

// newAttrList builds a ProcThreadAttributeList that binds the process to the given HPCON.
func newAttrList(hpc windows.Handle) (*windows.ProcThreadAttributeList, attrListMemory, error) {
	var size uintptr
	// First call to get required size
	r1, _, _ := procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if r1 != 0 {
		return nil, nil, fmt.Errorf("unexpected success on size query")
	}
	
	raw := make([]byte, size)
	al := (*windows.ProcThreadAttributeList)(unsafe.Pointer(&raw[0]))
	
	// Second call to initialize
	r1, _, e1 := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(al)),
		1,
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		return nil, nil, fmt.Errorf("InitializeProcThreadAttributeList failed: %v", e1)
	}
	
	// Update with ConPTY handle
	r1, _, e1 = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(al)),
		0,
		procThreadAttributePseudoConsole,
		uintptr(hpc),
		unsafe.Sizeof(hpc),
		0,
		0,
	)
	if r1 == 0 {
		procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(al)))
		return nil, nil, fmt.Errorf("UpdateProcThreadAttribute failed: %v", e1)
	}
	
	return al, raw, nil
}

func deleteProcThreadAttributeList(al *windows.ProcThreadAttributeList) {
	if al != nil {
		procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(al)))
	}
}
