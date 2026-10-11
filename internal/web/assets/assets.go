// Package assets owns the browser's embedded templates and same-origin static files.
// Transport handlers supply view models and response policy; no control domain
// imports this package.
package assets

import (
	"embed"
	"html/template"
)

//go:embed static/* templates/*.html templates/admin/*.html
var content embed.FS

func HTML(name string) []byte   { return mustRead("templates/" + name) }
func Static(name string) []byte { return mustRead("static/" + name) }

func AdminTemplate(functions template.FuncMap) (*template.Template, error) {
	return template.New("admin").Funcs(functions).ParseFS(content, "templates/admin/*.html")
}

func mustRead(path string) []byte {
	data, err := content.ReadFile(path)
	if err != nil {
		panic("missing embedded browser asset: " + path)
	}

	return data
}
