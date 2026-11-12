package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The picture a shared link shows, and the script that draws it, relative to
// this package. The script writes the stores it named and its own digest into
// the picture as PNG text under these keys.
var (
	picture       = filepath.Join("..", "..", "assets", "social-preview", "social-preview.png")
	pictureScript = filepath.Join("..", "..", "assets", "social-preview", "social_preview.py")
)

const (
	keyStores  = "certdoctor:stores"
	keyDrawnBy = "certdoctor:drawn-by"
)

// TestThePictureIsDrawnFromTodaysProgram fails when the picture GitHub and the
// website show is no longer what its script would draw today: the program asks
// a store the picture does not name, or the script changed and the picture was
// not drawn again. Nothing else notices - the website copies the picture rather
// than drawing it.
//
// What this does NOT check: that the pixels are what the script draws, or
// that GitHub has the same picture. GitHub keeps a copy uploaded by hand.
func TestThePictureIsDrawnFromTodaysProgram(t *testing.T) {
	png, err := os.ReadFile(picture)
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(pictureScript)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPicture(png, script, collect().Stores); err != nil {
		t.Errorf("%v\nDraw it again, look at it, commit it and upload it to GitHub under Settings, General, "+
			"Social preview:\n  go run ./cmd/sitefacts > web/data/facts/certdoctor.json\n"+
			"  python assets/social-preview/social_preview.py", err)
	}
}

// TestThePictureCheckCanFail is the canary: a picture naming one store too few,
// one drawn by another script, and bytes that are not a picture are refused,
// and the same picture with the right words is not.
func TestThePictureCheckCanFail(t *testing.T) {
	script := []byte("draw()\r\n")
	digest := scriptDigest([]byte("draw()\n"))
	stores := []string{"system-store", "java"}
	good := pngWith(map[string]string{keyStores: "system-store,java", keyDrawnBy: digest})
	if err := checkPicture(good, script, stores); err != nil {
		t.Fatalf("a picture matching the program was refused: %v", err)
	}
	refused := map[string][]byte{
		"a store left out":     pngWith(map[string]string{keyStores: "system-store", keyDrawnBy: digest}),
		"another script":       pngWith(map[string]string{keyStores: "system-store,java", keyDrawnBy: scriptDigest([]byte("x"))}),
		"no words at all":      pngWith(nil),
		"not a picture":        []byte("GIF89a"),
		"cut short in a chunk": good[:len(good)-6],
	}
	for name, bad := range refused {
		if checkPicture(bad, script, stores) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func checkPicture(png, script []byte, stores []string) error {
	words, err := pngText(png)
	if err != nil {
		return err
	}
	if drawn, want := words[keyDrawnBy], scriptDigest(script); drawn != want {
		return fmt.Errorf("the picture was drawn by another version of social_preview.py (%q, the script now is %q)",
			drawn, want)
	}
	if named, asked := words[keyStores], strings.Join(stores, ","); named != asked {
		return fmt.Errorf("the picture names the stores %q and the program asks %q", named, asked)
	}
	return nil
}

// scriptDigest reads the script with its line endings as git stores them, so
// a checkout on Windows hashes the same text as one on Linux.
func scriptDigest(script []byte) string {
	sum := sha256.Sum256(bytes.ReplaceAll(script, []byte("\r\n"), []byte("\n")))
	return hex.EncodeToString(sum[:])
}

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

// pngText answers the tEXt chunks of a PNG file, keyword to text. The standard
// library's decoder skips them, and this needs nothing else from the picture.
func pngText(png []byte) (map[string]string, error) {
	if !bytes.HasPrefix(png, pngSignature) {
		return nil, errors.New("the picture is not a PNG file")
	}
	words := map[string]string{}
	for rest := png[len(pngSignature):]; len(rest) > 0; {
		if len(rest) < 12 {
			return nil, errors.New("the picture ends inside a chunk")
		}
		size := int(binary.BigEndian.Uint32(rest))
		kind := string(rest[4:8])
		if size > len(rest)-12 {
			return nil, errors.New("the picture ends inside a chunk")
		}
		if kind == "tEXt" {
			if key, text, ok := bytes.Cut(rest[8:8+size], []byte{0}); ok {
				words[string(key)] = string(text)
			}
		}
		rest = rest[12+size:]
	}
	return words, nil
}

// pngWith builds the chunks pngText reads, without pixels: enough to hold
// words, and not a picture anything would show.
func pngWith(words map[string]string) []byte {
	out := append([]byte{}, pngSignature...)
	chunk := func(kind string, data []byte) {
		out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
		out = append(out, kind...)
		out = append(out, data...)
		out = append(out, 0, 0, 0, 0)
	}
	for key, text := range words {
		chunk("tEXt", append(append([]byte(key), 0), text...))
	}
	chunk("IEND", nil)
	return out
}
