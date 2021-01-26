package main

// Copyright (c) 2021 tick <tickelton@gmail.com>
// SPDX-License-Identifier:	ISC

import (
	"fmt"
	"image/color"
	"image/gif"
	"log"
	"os"
)

func usage() {
	fmt.Println(
		"Usage: ",
		os.Args[0],
		" FILENAME",
	)
}

func main() {
	if len(os.Args[1:]) != 1 {
		usage()
		return
	}
	reader, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	defer reader.Close()

	g, err := gif.DecodeAll(reader)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < len(g.Image); i++ {
		fmt.Println("color.Palette{")
		for j := 0; j < len(g.Image[i].Palette); j++ {
			entry, ok := g.Image[i].Palette[j].(color.RGBA)
			if ok {
				fmt.Printf(
					"\tcolor.RGBA{%#02x, %#02x, %#02x, %#02x},\n",
					entry.R,
					entry.G,
					entry.B,
					entry.A,
				)
			}
		}
		fmt.Println("}")
	}
}
