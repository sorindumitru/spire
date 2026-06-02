package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestStringVarS(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})

	var val string
	fs.StringVarS(&val, "config", "c", "", "Path to config file")

	t.Run("long flag", func(t *testing.T) {
		val = ""
		if err := fs.Parse([]string{"-config", "/etc/spire.conf"}); err != nil {
			t.Fatal(err)
		}
		if val != "/etc/spire.conf" {
			t.Fatalf("expected /etc/spire.conf, got %q", val)
		}
	})

	t.Run("short flag", func(t *testing.T) {
		val = ""
		if err := fs.Parse([]string{"-c", "/etc/other.conf"}); err != nil {
			t.Fatal(err)
		}
		if val != "/etc/other.conf" {
			t.Fatalf("expected /etc/other.conf, got %q", val)
		}
	})
}

func TestBoolVarS(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})

	var val bool
	fs.BoolVarS(&val, "verbose", "v", false, "Enable verbose output")

	val = false
	if err := fs.Parse([]string{"-v"}); err != nil {
		t.Fatal(err)
	}
	if !val {
		t.Fatal("expected true")
	}
}

func TestIntVarS(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})

	var val int
	fs.IntVarS(&val, "port", "p", 8080, "Port number")

	if err := fs.Parse([]string{"-p", "9090"}); err != nil {
		t.Fatal(err)
	}
	if val != 9090 {
		t.Fatalf("expected 9090, got %d", val)
	}
}

func TestInt64VarS(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})

	var val int64
	fs.Int64VarS(&val, "expiry", "e", 0, "Expiry time")

	if err := fs.Parse([]string{"-e", "12345"}); err != nil {
		t.Fatal(err)
	}
	if val != 12345 {
		t.Fatalf("expected 12345, got %d", val)
	}
}

func TestVarS(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})

	var val StringsFlag
	fs.VarS(&val, "selector", "S", "A selector")

	if err := fs.Parse([]string{"-S", "unix:uid:1000", "-selector", "spiffe_id:foo"}); err != nil {
		t.Fatal(err)
	}
	if len(val) != 2 {
		t.Fatalf("expected 2 values, got %d", len(val))
	}
}

func TestNoShortAlias(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})

	var val string
	fs.StringVarS(&val, "config", "", "default", "Path to config file")

	if err := fs.Parse([]string{"-config", "test.conf"}); err != nil {
		t.Fatal(err)
	}
	if val != "test.conf" {
		t.Fatalf("expected test.conf, got %q", val)
	}
}

func TestPromotedMethods(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})

	var val string
	fs.StringVar(&val, "config", "", "Path to config file")

	if err := fs.Parse([]string{"-config", "test.conf"}); err != nil {
		t.Fatal(err)
	}
	if val != "test.conf" {
		t.Fatalf("expected test.conf, got %q", val)
	}
}

func TestUsageOutput(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	var config string
	var verbose bool
	var count int
	fs.StringVarS(&config, "config", "c", "", "Path to config file")
	fs.BoolVarS(&verbose, "verbose", "v", false, "Enable verbose output")
	fs.IntVar(&count, "count", 0, "Number of items")

	fs.Usage()
	output := buf.String()

	if !strings.Contains(output, "Usage of test:") {
		t.Fatalf("expected 'Usage of test:' header, got:\n%s", output)
	}
	if !strings.Contains(output, "-config, -c string") {
		t.Fatalf("expected combined '-config, -c string' in usage output, got:\n%s", output)
	}
	if !strings.Contains(output, "-verbose, -v") {
		t.Fatalf("expected combined -verbose, -v in usage output, got:\n%s", output)
	}
	if !strings.Contains(output, "-count int") {
		t.Fatalf("expected '-count int' in usage output, got:\n%s", output)
	}
	if strings.Contains(output, "  -c\n") || strings.Contains(output, "  -c ") {
		t.Fatalf("short alias -c should not appear as standalone entry, got:\n%s", output)
	}
	if strings.Contains(output, "  -v\n") || strings.Contains(output, "  -v ") {
		t.Fatalf("short alias -v should not appear as standalone entry, got:\n%s", output)
	}
}

func TestUsageWithDefaults(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	var config string
	fs.StringVarS(&config, "config", "c", "/etc/spire.conf", "Path to config file")

	fs.Usage()
	output := buf.String()

	if !strings.Contains(output, `(default "/etc/spire.conf")`) {
		t.Fatalf("expected default value in usage output, got:\n%s", output)
	}
}

func TestUsageZeroDefaults(t *testing.T) {
	fs := NewFlagSet("test", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	var s string
	var b bool
	var i int
	fs.StringVar(&s, "str", "", "A string")
	fs.BoolVar(&b, "bool", false, "A bool")
	fs.IntVar(&i, "int", 0, "An int")

	fs.Usage()
	output := buf.String()

	if strings.Contains(output, "default") {
		t.Fatalf("zero-value defaults should not be shown, got:\n%s", output)
	}
}
