package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("specify a network interface")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	var objs pingerObjects
	if err := loadPingerObjects(&objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}

	}
	defer objs.Close()

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Pinger,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("attached to %s", ifaceName)

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			log.Print("received signal, exiting..")
			return
		}
	}
}
