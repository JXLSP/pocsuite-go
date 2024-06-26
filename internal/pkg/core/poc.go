package core

type BasePoc struct {
	VulnID     string
	Version    string
	Author     string
	VulnDate   string
	CreateDate string
	UpdateDAte string
	VulnType   string
	Desc       string
	References string
}

func (b *BasePoc) PrintPocInfo() {}
