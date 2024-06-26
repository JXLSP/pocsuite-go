package pocs

import "github.com/seaung/pocsuite-go/internal/pkg/core"

type DemoPoc struct {
    core.BasePoc
}

func (d *DemoPoc) Verify(target string, params map[string]any) bool {
    return false
}

func (d *DemoPoc) Attack(target string, params map[string]any) {}

