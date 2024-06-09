package embeded

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"

	"github.com/labstack/echo/v4"
)

//go:embed static/*
var static embed.FS

func Static() fs.FS {
	staticFS, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	return staticFS
}

//go:embed layouts partials
var templateFiles embed.FS

type Template struct {
	templates *template.Template
	views     map[string]*template.Template
}

func (t *Template) Render(w io.Writer, vName string, data any, c echo.Context) error {
	view, ok := t.views[vName]
	if !ok {
		panic(fmt.Sprintf("invalid view name:: %q", vName))
	}
	err := view.Execute(w, data)
	if err != nil {
		panic(err)
	}
	return nil
}

func (t *Template) NewView(name, base string, partials ...string) {
	if _, ok := t.views[name]; ok {
		panic(fmt.Errorf("view with name %q already registered.", name))
	}

	all := make([]string, len(partials)+1)
	all[0] = fmt.Sprintf("layouts/%s", base)
	for i, p := range partials {
		all[i+1] = fmt.Sprintf("partials/%s", p)
	}

	view := template.Must(template.New(base).Funcs(
		template.FuncMap{
			"safeHTML": safeHTML,
		},
	).ParseFS(templateFiles, all...))
	t.views[name] = view
}

func Templates() *Template {
	return &Template{
		views: map[string]*template.Template{},
	}
}

func safeHTML(str string) template.HTML {
	return template.HTML(str)
}
