package utils

import (
	"bytes"
	"fmt"
	"html"
	"strings"
)

type Markup struct {
	content []string
	mode    string
	case_   string
}

func NewMarkup() *Markup {
	return &Markup{
		content: make([]string, 0),
		mode:    "html",
		case_:   "lower",
	}
}

func (m *Markup) SetMode(mode string) {
	m.mode = mode
}

func (m *Markup) SetCase(case_ string) {
	m.case_ = case_
}

func (m *Markup) Add(content string) {
	m.content = append(m.content, content)
}

func (m *Markup) AddElement(tag string, attrs map[string]string, content string) {
	tag = m.processTagName(tag)

	var buf bytes.Buffer
	buf.WriteString("<" + tag)

	for key, value := range attrs {
		key = strings.ReplaceAll(key, "_", "-")
		if value == "" {
			buf.WriteString(" " + key)
		} else {
			buf.WriteString(fmt.Sprintf(" %s=\"%s\"", key, html.EscapeString(value)))
		}
	}

	if content == "" {
		buf.WriteString(" />")
	} else {
		buf.WriteString(">" + html.EscapeString(content) + "</" + tag + ">")
	}

	m.content = append(m.content, buf.String())
}

func (m *Markup) AddOpenTag(tag string, attrs map[string]string) {
	tag = m.processTagName(tag)

	var buf bytes.Buffer
	buf.WriteString("<" + tag)

	for key, value := range attrs {
		key = strings.ReplaceAll(key, "_", "-")
		if value == "" {
			buf.WriteString(" " + key)
		} else {
			buf.WriteString(fmt.Sprintf(" %s=\"%s\"", key, html.EscapeString(value)))
		}
	}

	buf.WriteString(">")
	m.content = append(m.content, buf.String())
}

func (m *Markup) AddCloseTag(tag string) {
	tag = m.processTagName(tag)
	m.content = append(m.content, "</"+tag+">")
}

func (m *Markup) AddComment(comment string) {
	m.content = append(m.content, "<!--"+html.EscapeString(comment)+"-->")
}

func (m *Markup) AddCDATA(data string) {
	m.content = append(m.content, "<![CDATA["+data+"]]>")
}

func (m *Markup) AddDoctype(doctype string) {
	m.content = append(m.content, "<!DOCTYPE "+doctype+">")
}

func (m *Markup) String() string {
	return strings.Join(m.content, "\n")
}

func (m *Markup) Bytes() []byte {
	return []byte(m.String())
}

func (m *Markup) Clear() {
	m.content = make([]string, 0)
}

func (m *Markup) processTagName(tag string) string {
	switch m.case_ {
	case "upper":
		return strings.ToUpper(tag)
	case "lower":
		return strings.ToLower(tag)
	case "given":
		return tag
	default:
		return strings.ToLower(tag)
	}
}

func Escape(s string) string {
	return html.EscapeString(s)
}

func Unescape(s string) string {
	return html.UnescapeString(s)
}

func Attribute(key, value string) map[string]string {
	return map[string]string{key: value}
}

func Attributes(pairs ...string) map[string]string {
	if len(pairs)%2 != 0 {
		panic("Attributes requires an even number of arguments")
	}

	attrs := make(map[string]string)
	for i := 0; i < len(pairs); i += 2 {
		attrs[pairs[i]] = pairs[i+1]
	}
	return attrs
}

type HTMLBuilder struct {
	markup *Markup
}

func NewHTMLBuilder() *HTMLBuilder {
	return &HTMLBuilder{
		markup: NewMarkup(),
	}
}

func (hb *HTMLBuilder) Doctype(doctype string) *HTMLBuilder {
	hb.markup.AddDoctype(doctype)
	return hb
}

func (hb *HTMLBuilder) HTML5() *HTMLBuilder {
	return hb.Doctype("html")
}

func (hb *HTMLBuilder) Tag(tag string, attrs map[string]string, content string) *HTMLBuilder {
	hb.markup.AddElement(tag, attrs, content)
	return hb
}

func (hb *HTMLBuilder) OpenTag(tag string, attrs map[string]string) *HTMLBuilder {
	hb.markup.AddOpenTag(tag, attrs)
	return hb
}

func (hb *HTMLBuilder) CloseTag(tag string) *HTMLBuilder {
	hb.markup.AddCloseTag(tag)
	return hb
}

func (hb *HTMLBuilder) Comment(comment string) *HTMLBuilder {
	hb.markup.AddComment(comment)
	return hb
}

func (hb *HTMLBuilder) Text(text string) *HTMLBuilder {
	hb.markup.Add(Escape(text))
	return hb
}

func (hb *HTMLBuilder) Raw(content string) *HTMLBuilder {
	hb.markup.Add(content)
	return hb
}

func (hb *HTMLBuilder) String() string {
	return hb.markup.String()
}

func (hb *HTMLBuilder) Bytes() []byte {
	return hb.markup.Bytes()
}

func (hb *HTMLBuilder) Clear() *HTMLBuilder {
	hb.markup.Clear()
	return hb
}

func (hb *HTMLBuilder) Div(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("div", attrs, content)
}

func (hb *HTMLBuilder) Span(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("span", attrs, content)
}

func (hb *HTMLBuilder) P(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("p", attrs, content)
}

func (hb *HTMLBuilder) A(href, text string) *HTMLBuilder {
	return hb.Tag("a", Attributes("href", href), text)
}

func (hb *HTMLBuilder) Img(src, alt string) *HTMLBuilder {
	return hb.Tag("img", Attributes("src", src, "alt", alt), "")
}

func (hb *HTMLBuilder) Br() *HTMLBuilder {
	return hb.Tag("br", nil, "")
}

func (hb *HTMLBuilder) Hr() *HTMLBuilder {
	return hb.Tag("hr", nil, "")
}

func (hb *HTMLBuilder) Table(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("table", attrs, content)
}

func (hb *HTMLBuilder) Tr(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("tr", attrs, content)
}

func (hb *HTMLBuilder) Td(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("td", attrs, content)
}

func (hb *HTMLBuilder) Th(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("th", attrs, content)
}

func (hb *HTMLBuilder) Ul(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("ul", attrs, content)
}

func (hb *HTMLBuilder) Ol(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("ol", attrs, content)
}

func (hb *HTMLBuilder) Li(attrs map[string]string, content string) *HTMLBuilder {
	return hb.Tag("li", attrs, content)
}

func (hb *HTMLBuilder) Form(action, method string, content string) *HTMLBuilder {
	return hb.Tag("form", Attributes("action", action, "method", method), content)
}

func (hb *HTMLBuilder) Input(inputType, name, value string) *HTMLBuilder {
	return hb.Tag("input", Attributes("type", inputType, "name", name, "value", value), "")
}

func (hb *HTMLBuilder) Button(buttonType, name, value, content string) *HTMLBuilder {
	return hb.Tag("button", Attributes("type", buttonType, "name", name, "value", value), content)
}

func (hb *HTMLBuilder) Select(name string, content string) *HTMLBuilder {
	return hb.Tag("select", Attributes("name", name), content)
}

func (hb *HTMLBuilder) Option(value, text string, selected bool) *HTMLBuilder {
	attrs := Attributes("value", value)
	if selected {
		attrs["selected"] = ""
	}
	return hb.Tag("option", attrs, text)
}

func (hb *HTMLBuilder) Textarea(name, content string) *HTMLBuilder {
	return hb.Tag("textarea", Attributes("name", name), content)
}

func (hb *HTMLBuilder) H1(content string) *HTMLBuilder {
	return hb.Tag("h1", nil, content)
}

func (hb *HTMLBuilder) H2(content string) *HTMLBuilder {
	return hb.Tag("h2", nil, content)
}

func (hb *HTMLBuilder) H3(content string) *HTMLBuilder {
	return hb.Tag("h3", nil, content)
}

func (hb *HTMLBuilder) H4(content string) *HTMLBuilder {
	return hb.Tag("h4", nil, content)
}

func (hb *HTMLBuilder) H5(content string) *HTMLBuilder {
	return hb.Tag("h5", nil, content)
}

func (hb *HTMLBuilder) H6(content string) *HTMLBuilder {
	return hb.Tag("h6", nil, content)
}

func (hb *HTMLBuilder) Strong(content string) *HTMLBuilder {
	return hb.Tag("strong", nil, content)
}

func (hb *HTMLBuilder) Em(content string) *HTMLBuilder {
	return hb.Tag("em", nil, content)
}

func (hb *HTMLBuilder) Code(content string) *HTMLBuilder {
	return hb.Tag("code", nil, content)
}

func (hb *HTMLBuilder) Pre(content string) *HTMLBuilder {
	return hb.Tag("pre", nil, content)
}

func (hb *HTMLBuilder) Blockquote(content string) *HTMLBuilder {
	return hb.Tag("blockquote", nil, content)
}
