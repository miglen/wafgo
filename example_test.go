package wafgo_test

import (
	"context"
	"fmt"

	"github.com/miglen/wafgo"
)

func ExampleEngine_Scan() {
	eng, err := wafgo.New(wafgo.Options{FindAll: true})
	if err != nil {
		panic(err)
	}
	rep, err := eng.Scan(context.Background(), "https://example.com")
	if err != nil {
		return // site down or invalid target
	}
	for _, w := range rep.WAFs {
		fmt.Printf("%s (%s)\n", w.Product(), rep.Enforcement)
	}
}
