package modules

import (
	"github.com/seaung/pocsuite-go/modules/interfaces"
	"github.com/seaung/pocsuite-go/modules/manager"
)

type Module = interfaces.Module
type Searcher = interfaces.Searcher
type OASTService = interfaces.OASTService
type VulnerabilityDB = interfaces.VulnerabilityDB
type HTTPServer = interfaces.HTTPServer
type Listener = interfaces.ListenerModule
type Spider = interfaces.Spider
type Shellcodes = interfaces.Shellcodes

type ModuleManager = manager.ModuleManager
