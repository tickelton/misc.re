package main

import (
	"fmt"
	"image/gif"
	"log"
	"os"
)

func main() {
	reader, err := os.Open("/media/ramdisk/rgb.gif")
	if err != nil {
		log.Fatal(err)
	}

	defer reader.Close()

	g, err := gif.DecodeAll(reader)
	fmt.Println(g.Image[0].Palette[4])
}
