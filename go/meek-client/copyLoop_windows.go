// +build windows
package main

import (
	"bufio"
	"log"
	"net"
	"syscall"
	"time"
)

// Repeatedly read from conn, issue HTTP requests, and write the responses back
// to conn.
func copyLoop(conn net.Conn, info *RequestInfo) error {
	var interval time.Duration

	ch := make(chan []byte)

	// Read from the Conn and send byte slices on the channel.
	go func() {
		var buf [maxPayloadLength]byte
		r := bufio.NewReader(conn)
		for {
			n, err := r.Read(buf[:])
			b := make([]byte, n)
			copy(b, buf[:n])
			// log.Printf("read from local: %q", b)
			ch <- b
			if err != nil {
				log.Printf("error reading from local: %s", err)
				break
			}
		}
		close(ch)
	}()

	interval = initPollInterval
loop:
	for {
		var buf []byte
		var ok bool

		// log.Printf("waiting up to %.2f s", interval.Seconds())
		// start := time.Now()
		select {
		case buf, ok = <-ch:
			if !ok {
				break loop
			}
			// log.Printf("read %d bytes from local after %.2f s", len(buf), time.Since(start).Seconds())
		case <-time.After(interval):
			// log.Printf("read nothing from local after %.2f s", time.Since(start).Seconds())
			buf = nil
		}

		nw, err := sendRecv(buf, conn, info)
		if err != nil {
			//Ignore peer disconnect
			operr, ok := err.(*net.OpError)
			if !ok {
				return err
			}
			errno, ok := operr.Err.(syscall.Errno)
			if !ok {
				return err
			}
			switch errno {
			case syscall.ERROR_NETNAME_DELETED, syscall.WSAECONNRESET:
				return nil
			}
			return err
		}
		/*
			if nw > 0 {
				log.Printf("got %d bytes from remote", nw)
			} else {
				log.Printf("got nothing from remote")
			}
		*/

		if nw > 0 || len(buf) > 0 {
			// If we sent or received anything, poll again
			// immediately.
			interval = 0
		} else if interval == 0 {
			// The first time we don't send or receive anything,
			// wait a while.
			interval = initPollInterval
		} else {
			// After that, wait a little longer.
			interval = time.Duration(float64(interval) * pollIntervalMultiplier)
		}
		if interval > maxPollInterval {
			interval = maxPollInterval
		}
	}

	return nil
}
