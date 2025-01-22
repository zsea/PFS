package main

import (
	"flag"
	"fmt"
	"strings"
)

type Argument struct {
	LongName     string
	ShortName    string
	DefaultValue string
	Usage        string
	Type         string
}
type Arguments []Argument

var Usages Arguments

func (a *Arguments) AppendString(p *string, shortName string, longName string, value string, usage string) {
	argument := Argument{
		LongName:     longName,
		ShortName:    shortName,
		DefaultValue: value,
		Usage:        usage,
		Type:         "string",
	}
	if len(shortName) > 0 {
		flag.StringVar(p, shortName, value, usage)
	}
	if len(longName) > 0 {
		flag.StringVar(p, longName, value, usage)
	}
	Usages = append(Usages, argument)
}
func (a *Arguments) AppendBool(p *bool, shortName string, longName string, value bool, usage string) {
	argument := Argument{
		LongName:     longName,
		ShortName:    shortName,
		DefaultValue: map[bool]string{true: "true", false: "false"}[value],
		Usage:        usage,
		Type:         "bool",
	}
	if len(shortName) > 0 {
		flag.BoolVar(p, shortName, value, usage)
	}
	if len(longName) > 0 {
		flag.BoolVar(p, longName, value, usage)
	}
	Usages = append(Usages, argument)
}
func (a *Arguments) Parse() {
	flag.Parse()
}
func (a *Arguments) Usages() {
	fmt.Println("Usage:")
	for _, argument := range *a {
		line := ""
		var names []string
		if len(argument.ShortName) > 0 {
			names = append(names, "-"+argument.ShortName)
		}
		if len(argument.LongName) > 0 {
			names = append(names, "--"+argument.LongName)
		}
		line = line + strings.Join(names, ", ")
		if argument.Type != "bool" {
			line = line + "\t" + argument.Type
			if len(argument.DefaultValue) > 0 {
				line = line + "[" + argument.DefaultValue + "]"
			}
		}
		fmt.Printf("  %s\n    \t%s\n", line, argument.Usage)
	}
}
