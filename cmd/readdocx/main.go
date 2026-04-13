package main

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// WordDocument represents the root XML element of word/document.xml
type WordDocument struct {
	XMLName xml.Name `xml:"document"`
	Body    Body     `xml:"body"`
}

type Body struct {
	Paragraphs []Paragraph `xml:"p"`
}

type Paragraph struct {
	Runs []Run `xml:"r"`
}

type Run struct {
	Text Text `xml:"t"`
}

type Text struct {
	Value string `xml:",chardata"`
}

func extractDocxText(path string) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("failed to open docx: %w", err)
	}
	defer r.Close()

	var docFile *zip.File
	for _, f := range r.File {
		if f.Name == "word/document.xml" {
			docFile = f
			break
		}
	}
	if docFile == nil {
		return "", fmt.Errorf("word/document.xml not found in docx")
	}

	rc, err := docFile.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open word/document.xml: %w", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return "", fmt.Errorf("failed to read word/document.xml: %w", err)
	}

	// Use a token-based approach to extract all text nodes within <w:p> paragraphs
	// This is more robust than struct-based unmarshalling for complex Word XML
	type wText struct {
		XMLName xml.Name `xml:"t"`
		Space   string   `xml:"space,attr"`
		Value   string   `xml:",chardata"`
	}

	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	var paragraphs []string
	var currentPara strings.Builder
	inParagraph := false

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("XML parse error: %w", err)
		}

		switch se := token.(type) {
		case xml.StartElement:
			localName := se.Name.Local
			if localName == "p" {
				inParagraph = true
				currentPara.Reset()
			} else if localName == "t" && inParagraph {
				var t wText
				if err := decoder.DecodeElement(&t, &se); err == nil {
					currentPara.WriteString(t.Value)
				}
			}
		case xml.EndElement:
			if se.Name.Local == "p" && inParagraph {
				paragraphs = append(paragraphs, currentPara.String())
				inParagraph = false
			}
		}
	}

	return strings.Join(paragraphs, "\n"), nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: readdocx <file.docx>")
	}
	path := os.Args[1]

	text, err := extractDocxText(path)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Println(text)
}
