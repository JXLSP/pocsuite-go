package pocs

type Pocser interface {
	Attack(target string, params map[string]any)
	Verify(target string, params map[string]any) bool
}
