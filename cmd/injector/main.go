package main

import (
	"fmt"
	proc_injector "inject"
	"os"
	"strconv"
)

func main() {
	var pidStr = os.Args[1]
	pidint64, err := strconv.ParseInt(pidStr, 10, 64)
	if err != nil {
		panic(err)
	}
	fmt.Println("pid:", pidint64)
	var inj = proc_injector.NewInjector(int(pidint64))
	inj.Inject(int(pidint64))
}
