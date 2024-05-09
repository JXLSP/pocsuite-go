package utils

import "runtime"

func GetOSPlatform() string {
    return runtime.GOOS
}

