// cr is a program to encrypt and decrypt files.
//
// Usage is:
//    cr fileName
// or to write to disk:
//    cr -w fileName
//
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/jroimartin/gocui"
	"golang.org/x/crypto/ssh/terminal"
)

const extension string = ".cr"

var clearTextData []byte
var encFile string
var pwd string

func main() {
	w := flag.Bool("w", false, "write to disk")
	v := flag.Bool("v", false, "version")
	flag.Parse()

	if *v {
		fmt.Println("cr version 1.2.1")
		return
	}

	var file string

	// si no se incluye el nombre del archivo
	if len(os.Args) < 2 {
		var err error
		file, err = getFile()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if file == "" {
			fmt.Println("cr encrypts and decrypts files.")
			flag.Usage()
			os.Exit(1)
		}
	} else {
		// el ultimo argumento es el archivo
		file = os.Args[len(os.Args)-1]
	}

	restoreIfInterrupt()

	run(file, *w)
}

func run(file string, writeToDisk bool) {
	// don't append anything to the std log.
	log.SetFlags(0)

	if _, err := os.Stat(file); os.IsNotExist(err) {
		log.Fatalf("No such file %s", file)
		return
	}

	isPlainText := filepath.Ext(file) != extension

	pwd := readPassword(isPlainText)

	if isPlainText {
		encryptFile(file, pwd)
		return
	}

	decryptFile(file, pwd, writeToDisk)
}

// previene que se quede el cursor invisible si se aborta con Ctrl+C
func restoreIfInterrupt() {
	fd := int(os.Stdin.Fd())

	oldState, err := terminal.GetState(fd)
	if err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		terminal.Restore(fd, oldState)
		fmt.Println()
		os.Exit(1)
	}()
}

func readPassword(confirm bool) string {
	fmt.Print("Password: ")
	pwd, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print("\n")

	if confirm {
		fmt.Print("Repeat password: ")
		pwd2, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Print("\n")
		if string(pwd) != string(pwd2) {
			log.Fatal("Error: Passwords are different")
		}

		if len(pwd) < 8 {
			log.Println("Warning: the password is very short.")
		}
	}

	return string(pwd)
}

// crea un archivo encriptado a partir de file añadiendole una
// extensión y borra el archivo original.
func encryptFile(file, password string) {
	key := []byte(password)
	text, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	e, err := Encrypt(text, key)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(file+extension, e, 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.Remove(file)
	if err != nil {
		log.Fatal("Error deleting file: " + err.Error())
	}
}

// encripta data en fileName
func encryptToFile(data []byte, password, fileName string) error {
	key := []byte(password)
	e, err := Encrypt(data, key)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fileName, e, 0644)
	if err != nil {
		return fmt.Errorf("Error escribiendo en %s", fileName)
	}

	return nil
}

func decryptFile(file, password string, writeToDisk bool) {
	key := []byte(password)
	text, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := Decrypt(text, key)
	if err != nil {
		log.Fatal(err)
	}

	if !writeToDisk {
		clearTextData = decrypted
		pwd = password
		encFile = file
		initEditor()
		return
	}

	// crear el archivo desencriptado
	plainFile := file[:len(file)-len(extension)]
	err = ioutil.WriteFile(plainFile, decrypted, 0644)
	if err != nil {
		log.Fatal(err)
	}

	// borrar el encriptado
	err = os.Remove(file)
	if err != nil {
		log.Fatal("Error deleting file: " + err.Error())
	}
}

// Pbtiene el único archivo encriptado del directorio,
// Si encuentra varios devuelve un string vacio.
func getFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}

	file := ""
	for _, f := range files {
		fName := filepath.Join(dir, f.Name())
		if filepath.Ext(fName) == ".cr" {
			if file != "" {
				// si hay mas de un archivo con la extensión, no devolver nada.
				return "", nil
			}
			file = fName
		}
	}

	return file, nil
}

// sale del editor
func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func saveMain(g *gocui.Gui, v *gocui.View) error {
	v.Rewind()

	var err error
	clearTextData, err := ioutil.ReadAll(v)
	if err != nil {
		return err
	}

	err = encryptToFile(clearTextData, pwd, encFile)
	if err != nil {
		return err
	}

	return gocui.ErrQuit
}

func keybindings(g *gocui.Gui) error {
	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyCtrlS, gocui.ModNone, saveMain); err != nil {
		return err
	}
	return nil
}

func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("main", -1, -1, maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}

		v.Write(clearTextData)
		v.Editable = true
		v.Wrap = true
		if _, err := g.SetCurrentView("main"); err != nil {
			return err
		}
	}
	return nil
}

func initEditor() {
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Panicln(err)
	}
	defer g.Close()

	g.SetManagerFunc(layout)
	if err := keybindings(g); err != nil {
		log.Panicln(err)
	}
	g.SelBgColor = gocui.ColorGreen
	g.SelFgColor = gocui.ColorBlack
	g.Cursor = true

	err = g.MainLoop()
	if err != nil && err != gocui.ErrQuit {
		log.Panicln(err)
	}
}
