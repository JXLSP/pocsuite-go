package log

import (
	"fmt"

	"github.com/fatih/color"
)

type Logger struct {}

func NewLogger() *Logger {
    return &Logger{}
}

func (l *Logger) Debug(msg string) {
    highlight := color.New(color.FgWhite).SprintFunc()
    reset := color.New(color.FgWhite).SprintFunc()
    fmt.Println(highlight("[-]"), reset(msg))
}

func (l *Logger) Info(msg string) {
    highlight := color.New(color.FgBlue).SprintFunc()
    reset := color.New(color.FgWhite).SprintFunc()
    fmt.Println(highlight("[+]"), reset(msg))
}

func (l *Logger) Warn(msg string) {
    highlight := color.New(color.FgYellow).SprintFunc()
    fmt.Println(highlight("[!]"), highlight(msg))
}

func (l *Logger) Success(msg string) {
    highlight := color.New(color.FgGreen).SprintFunc()
    fmt.Println(highlight("[*]"), highlight(msg))
}

func (l *Logger) Err(msg string) {
    highlight := color.New(color.FgRed).SprintFunc()
    fmt.Println(highlight("[x]"), highlight(msg))
}

