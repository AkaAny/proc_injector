package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("pid:%d suspend for res\n", os.Getpid())
	go func() {
		for {

		}
	}()
	var interruptChan = make(chan int)
	<-interruptChan
}
