package main

import (
	"fmt"
	"image/color"
	"image/gif"
	"log"
	"os"
)

func main() {
	reader, err := os.Open("animated.gif")
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
