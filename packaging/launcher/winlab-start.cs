// winlab-start.exe: what the Start menu and desktop shortcuts run.
//
// winlab.exe is a console program (so `winlab lab up` prints where it was
// typed). Started from a shortcut, that console would be an empty black
// window beside the app. This launcher, a Windows program with no console of
// its own, starts winlab.exe next to it with no console window
// (CreateNoWindow) and ends; winlab then opens its own app window, and closing
// that window stops winlab. The launcher's arguments are passed on.
//
// Built by packaging\build-exe.ps1 with the C# compiler that is part of
// Windows' .NET Framework (csc.exe /target:winexe); nothing third-party.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("winlab")]
[assembly: AssemblyProduct("winlab")]
[assembly: AssemblyDescription("Starts winlab without a console window")]

static class WinlabStart
{
    static string Quote(string a)
    {
        if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
        var sb = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in a)
        {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') sb.Append('\\', slashes * 2 + 1);
            else sb.Append('\\', slashes);
            slashes = 0;
            sb.Append(c);
        }
        sb.Append('\\', slashes * 2).Append('"');
        return sb.ToString();
    }

    [STAThread]
    static int Main(string[] args)
    {
        string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        string exe = Path.Combine(dir, "winlab.exe");
        var psi = new ProcessStartInfo(exe, string.Join(" ", Array.ConvertAll(args, Quote)));
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.WorkingDirectory = dir;
        psi.EnvironmentVariables["WINLAB_QUIET"] = "1";
        try
        {
            Process.Start(psi);
            return 0;
        }
        catch (Exception e)
        {
            MessageBox.Show("winlab could not start:\n" + exe + "\n\n" + e.Message, "winlab",
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
