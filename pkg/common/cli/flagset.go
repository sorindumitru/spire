package cli

import (
	"flag"
	"fmt"
	"reflect"
	"strings"
)

// FlagSet wraps *flag.FlagSet to add short flag alias support with clean
// combined help output. Commands use the *VarS methods (e.g. StringVarS)
// to register flags with an optional short alias. The promoted *flag.FlagSet
// methods remain available for code that doesn't need short aliases.
type FlagSet struct {
	*flag.FlagSet
	shortToLong map[string]string
	longToShort map[string]string
}

// NewFlagSet creates a new FlagSet with custom usage output that combines
// short and long flag forms on one line.
func NewFlagSet(name string, errorHandling flag.ErrorHandling) *FlagSet {
	fs := &FlagSet{
		FlagSet:     flag.NewFlagSet(name, errorHandling),
		shortToLong: make(map[string]string),
		longToShort: make(map[string]string),
	}
	fs.FlagSet.Usage = fs.defaultUsage
	return fs
}

// StringVarS defines a string flag with a long name and optional short alias.
// If short is empty, no alias is registered.
func (fs *FlagSet) StringVarS(p *string, long, short, value, usage string) {
	fs.FlagSet.StringVar(p, long, value, usage)
	if short != "" {
		fs.FlagSet.StringVar(p, short, value, usage)
		fs.shortToLong[short] = long
		fs.longToShort[long] = short
	}
}

// BoolVarS defines a bool flag with a long name and optional short alias.
func (fs *FlagSet) BoolVarS(p *bool, long, short string, value bool, usage string) {
	fs.FlagSet.BoolVar(p, long, value, usage)
	if short != "" {
		fs.FlagSet.BoolVar(p, short, value, usage)
		fs.shortToLong[short] = long
		fs.longToShort[long] = short
	}
}

// IntVarS defines an int flag with a long name and optional short alias.
func (fs *FlagSet) IntVarS(p *int, long, short string, value int, usage string) {
	fs.FlagSet.IntVar(p, long, value, usage)
	if short != "" {
		fs.FlagSet.IntVar(p, short, value, usage)
		fs.shortToLong[short] = long
		fs.longToShort[long] = short
	}
}

// Int64VarS defines an int64 flag with a long name and optional short alias.
func (fs *FlagSet) Int64VarS(p *int64, long, short string, value int64, usage string) {
	fs.FlagSet.Int64Var(p, long, value, usage)
	if short != "" {
		fs.FlagSet.Int64Var(p, short, value, usage)
		fs.shortToLong[short] = long
		fs.longToShort[long] = short
	}
}

// VarS defines a flag with a Value interface, long name, and optional short alias.
func (fs *FlagSet) VarS(val flag.Value, long, short, usage string) {
	fs.FlagSet.Var(val, long, usage)
	if short != "" {
		fs.FlagSet.Var(val, short, usage)
		fs.shortToLong[short] = long
		fs.longToShort[long] = short
	}
}

func (fs *FlagSet) defaultUsage() {
	fmt.Fprintf(fs.FlagSet.Output(), "Usage of %s:\n", fs.FlagSet.Name())
	fs.FlagSet.VisitAll(func(f *flag.Flag) {
		if _, isShort := fs.shortToLong[f.Name]; isShort {
			return
		}

		var b strings.Builder
		name, usage := flag.UnquoteUsage(f)
		if short, ok := fs.longToShort[f.Name]; ok {
			if name != "" {
				fmt.Fprintf(&b, "  -%s, -%s %s", f.Name, short, name)
			} else {
				fmt.Fprintf(&b, "  -%s, -%s", f.Name, short)
			}
		} else {
			if name != "" {
				fmt.Fprintf(&b, "  -%s %s", f.Name, name)
			} else {
				fmt.Fprintf(&b, "  -%s", f.Name)
			}
		}

		if b.Len() <= 4 {
			b.WriteString("\t")
		} else {
			b.WriteString("\n    \t")
		}
		b.WriteString(strings.ReplaceAll(usage, "\n", "\n    \t"))

		if !isZeroValue(f) {
			if name == "string" {
				fmt.Fprintf(&b, " (default %q)", f.DefValue)
			} else {
				fmt.Fprintf(&b, " (default %s)", f.DefValue)
			}
		}
		fmt.Fprint(fs.FlagSet.Output(), b.String(), "\n")
	})
}

func isZeroValue(f *flag.Flag) bool {
	// Create a zero value of the flag's Value type and compare its String()
	// output with the flag's default value.
	typ := reflect.TypeOf(f.Value)
	if typ.Kind() == reflect.Pointer {
		z := reflect.New(typ.Elem())
		if zv, ok := z.Interface().(flag.Value); ok {
			return f.DefValue == zv.String()
		}
	}
	return f.DefValue == ""
}
