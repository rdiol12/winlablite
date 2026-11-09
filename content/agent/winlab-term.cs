// winlab console host: Command Prompt and Windows PowerShell sessions for the
// desktop's console windows, carried over the machine's third serial port.
//
// The lab machines have no network path to the PC they run on, so a console
// travels the way the agent's commands do: over a serial line that QEMU joins
// to a loopback socket on the host. Windows itself draws the console: every
// session is a real pseudoconsole (ConPTY, Windows 10 1809 / Server 2019 and
// later) with cmd.exe or powershell.exe in it, signed in as the account the
// student types, so tab completion, colours, PSReadLine, history and Ctrl+C
// are Windows' own. Nothing here interprets a command.
//
// The line protocol, one ASCII line per message, payloads in base64:
//   host -> guest   HELLO | RESET
//                   OPEN <sid> <cmd|powershell> <cols> <rows> <admin 0|1>
//                   IN <sid> <b64> | SIZE <sid> <cols> <rows> | CLOSE <sid>
//   guest -> host   READY <build> <b64 os> <b64 computer>   (unsolicited, at start)
//                   HELLO <build> <b64 os> <b64 computer>   (the answer to HELLO)
//                   OUT <sid> <b64> | EXIT <sid> <code>
//
// Compiled at start by winlab-term.ps1 with Windows PowerShell 5.1's Add-Type,
// so this file stays within C# 5 (no string interpolation, no => members).
// Its SHA-256 is the build the desktop compares with its own copy.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Ports;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace WinlabTerm
{
    public static class Host
    {
        public const int MaxSessions = 8;

        static Stream line;
        static readonly object writeLock = new object();
        static readonly object sessionLock = new object();
        static readonly Dictionary<int, Session> sessions = new Dictionary<int, Session>();

        public static string Build = "";
        public static string OsName = "";
        public static string Computer = "";
        public static string DomainDns = "";
        public static bool TestMode;      // no sign-in: sessions run as this host's own account (CI)
        public static string LogPath = "";

        public static void Log(string msg)
        {
            if (string.IsNullOrEmpty(LogPath)) return;
            try
            {
                File.AppendAllText(LogPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + "\r\n");
            }
            catch (Exception) { }
        }

        static string B64(string s)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(s ?? ""));
        }

        // Serves forever: on a serial port it reopens the port after an
        // error; on a TCP listener (tests only) it takes one client at a time.
        public static void Run(string com, string listen)
        {
            Native.EnablePrivileges();
            Log("console host " + Build + " starting on " + (string.IsNullOrEmpty(listen) ? com : listen));
            TcpListener listener = null;
            if (!string.IsNullOrEmpty(listen))
            {
                string[] hp = listen.Split(':');
                listener = new TcpListener(IPAddress.Parse(hp[0]), int.Parse(hp[1]));
                listener.Start();
            }
            while (true)
            {
                Stream s = null;
                TcpClient client = null;
                try
                {
                    if (listener != null)
                    {
                        client = listener.AcceptTcpClient();
                        client.NoDelay = true;
                        s = client.GetStream();
                    }
                    else
                    {
                        s = OpenSerial(com);
                    }
                    lock (writeLock) { line = s; }
                    Send("READY " + Build + " " + B64(OsName) + " " + B64(Computer));
                    ReadLoop(s);
                }
                catch (Exception ex)
                {
                    Log("line error: " + ex.Message);
                    Thread.Sleep(1000);
                }
                finally
                {
                    lock (writeLock) { line = null; }
                    if (listener != null) CloseAll();   // a test client's sessions end with it
                    try { if (s != null) s.Close(); } catch (Exception) { }
                    try { if (client != null) client.Close(); } catch (Exception) { }
                }
            }
        }

        static Stream OpenSerial(string com)
        {
            while (true)
            {
                try
                {
                    SerialPort p = new SerialPort(com, 115200, Parity.None, 8, StopBits.One);
                    p.Handshake = Handshake.None;
                    p.ReadBufferSize = 65536;
                    p.WriteBufferSize = 65536;
                    p.ReadTimeout = SerialPort.InfiniteTimeout;
                    p.WriteTimeout = 15000;
                    p.Open();
                    Log(com + " open");
                    return p.BaseStream;
                }
                catch (Exception ex)
                {
                    Log(com + " not available yet: " + ex.Message);
                    Thread.Sleep(3000);
                }
            }
        }

        public static void Send(string text)
        {
            byte[] b = Encoding.ASCII.GetBytes(text + "\n");
            lock (writeLock)
            {
                if (line == null) return;
                try
                {
                    line.Write(b, 0, b.Length);
                    line.Flush();
                }
                catch (Exception ex)
                {
                    Log("write error: " + ex.Message);
                }
            }
        }

        public static void SendOut(int sid, byte[] data, int count)
        {
            Send("OUT " + sid + " " + Convert.ToBase64String(data, 0, count));
        }

        static void ReadLoop(Stream s)
        {
            byte[] buf = new byte[8192];
            StringBuilder acc = new StringBuilder();
            while (true)
            {
                int n = s.Read(buf, 0, buf.Length);
                if (n <= 0) throw new IOException("the line closed");
                for (int i = 0; i < n; i++)
                {
                    char c = (char)buf[i];
                    if (c == '\n')
                    {
                        string msg = acc.ToString().Trim();
                        acc.Length = 0;
                        if (msg.Length > 0)
                        {
                            try { Dispatch(msg); }
                            catch (Exception ex) { Log("bad message: " + ex.Message); }
                        }
                    }
                    else if (acc.Length < 1048576)
                    {
                        acc.Append(c);
                    }
                }
            }
        }

        static Session Find(int sid)
        {
            lock (sessionLock)
            {
                Session x;
                return sessions.TryGetValue(sid, out x) ? x : null;
            }
        }

        public static void Forget(int sid)
        {
            lock (sessionLock) { sessions.Remove(sid); }
        }

        static void CloseAll()
        {
            List<Session> all;
            lock (sessionLock) { all = new List<Session>(sessions.Values); }
            foreach (Session x in all) x.Close();
        }

        static void Dispatch(string msg)
        {
            string[] f = msg.Split(' ');
            switch (f[0])
            {
                case "HELLO":
                    Send("HELLO " + Build + " " + B64(OsName) + " " + B64(Computer));
                    break;
                case "RESET":
                    CloseAll();
                    break;
                case "OPEN":
                    {
                        int sid = int.Parse(f[1]);
                        string shell = f[2] == "cmd" ? "cmd" : "powershell";
                        short cols = (short)Math.Max(20, Math.Min(500, int.Parse(f[3])));
                        short rows = (short)Math.Max(5, Math.Min(300, int.Parse(f[4])));
                        bool admin = f.Length > 5 && f[5] == "1";
                        Session x = new Session(sid, shell, cols, rows, admin);
                        bool full = false;
                        lock (sessionLock)
                        {
                            if (sessions.Count >= MaxSessions) full = true;
                            else sessions[sid] = x;
                        }
                        if (full)
                        {
                            byte[] m = Encoding.UTF8.GetBytes("This computer has " + MaxSessions + " consoles open already.\r\n");
                            SendOut(sid, m, m.Length);
                            Send("EXIT " + sid + " 1");
                        }
                        else x.Start();
                        break;
                    }
                case "IN":
                    {
                        Session x = Find(int.Parse(f[1]));
                        if (x != null && f.Length > 2) x.Input(Convert.FromBase64String(f[2]));
                        break;
                    }
                case "SIZE":
                    {
                        Session x = Find(int.Parse(f[1]));
                        if (x != null) x.Resize(short.Parse(f[2]), short.Parse(f[3]));
                        break;
                    }
                case "CLOSE":
                    {
                        Session x = Find(int.Parse(f[1]));
                        if (x != null) x.Close();
                        break;
                    }
            }
        }
    }

    // One console window: a sign-in prompt drawn here, then a pseudoconsole
    // with the shell in it.
    public class Session
    {
        readonly int sid;
        readonly string shell;
        short cols, rows;
        readonly bool admin;
        readonly object gate = new object();

        // the sign-in prompt
        int stage;              // 0 user name, 1 password, 2 signing in, 3 running, 4 closed
        string user = "";
        readonly StringBuilder typed = new StringBuilder();
        int escState;           // skipping an escape sequence the sign-in prompt has no use for
        int tries;

        // the running shell
        IntPtr hpc = IntPtr.Zero;
        IntPtr hProcess = IntPtr.Zero;
        IntPtr token = IntPtr.Zero;
        IntPtr profile = IntPtr.Zero;
        IntPtr env = IntPtr.Zero;
        FileStream input;
        FileStream output;
        Thread pump;
        bool exitSent;

        public Session(int sid, string shell, short cols, short rows, bool admin)
        {
            this.sid = sid;
            this.shell = shell;
            this.cols = cols;
            this.rows = rows;
            this.admin = admin;
        }

        void Write(string text)
        {
            byte[] b = Encoding.UTF8.GetBytes(text);
            Host.SendOut(sid, b, b.Length);
        }

        public void Start()
        {
            if (Host.TestMode)
            {
                stage = 2;
                ThreadPool.QueueUserWorkItem(delegate { Launch(IntPtr.Zero, Environment.UserName); });
                return;
            }
            Write("Sign in to " + Host.Computer + "\r\n");
            Write(Host.DomainDns.Length > 0
                ? "Use a domain account (" + Host.DomainDns.Split('.')[0].ToUpperInvariant() + "\\name) or an account of this computer.\r\n\r\n"
                : "Use an account of this computer.\r\n\r\n");
            Prompt();
        }

        void Prompt()
        {
            typed.Length = 0;
            if (stage == 0) Write("User name: ");
            else Write("Password: ");
        }

        public void Input(byte[] data)
        {
            lock (gate)
            {
                if (stage == 3)
                {
                    try
                    {
                        input.Write(data, 0, data.Length);
                        input.Flush();
                    }
                    catch (Exception) { }
                    return;
                }
                if (stage > 1) return;
                foreach (char c in Encoding.UTF8.GetString(data))
                {
                    if (stage > 1) break;
                    Key(c);
                }
            }
        }

        // The sign-in prompt's line editing: typing, Backspace, Enter, Ctrl+C.
        void Key(char c)
        {
            if (escState == 1) { escState = (c == '[' || c == 'O') ? 2 : 0; return; }
            if (escState == 2) { if (c >= '@' && c <= '~') escState = 0; return; }
            if (c == '\x1b') { escState = 1; return; }
            if (c == '\r' || c == '\n')
            {
                if (c == '\n') return;
                Write("\r\n");
                if (stage == 0)
                {
                    user = typed.ToString().Trim();
                    if (user.Length == 0) { Prompt(); return; }
                    stage = 1;
                    Prompt();
                }
                else
                {
                    string secret = typed.ToString();
                    typed.Length = 0;
                    stage = 2;
                    string who = user;
                    ThreadPool.QueueUserWorkItem(delegate { SignIn(who, secret); });
                }
                return;
            }
            if (c == '\x03')
            {
                Write("^C\r\n");
                stage = 0;
                Prompt();
                return;
            }
            if (c == '\x7f' || c == '\b')
            {
                if (typed.Length > 0)
                {
                    typed.Length -= 1;
                    if (stage == 0) Write("\b \b");
                }
                return;
            }
            if (c < ' ') return;
            if (typed.Length >= 256) return;
            typed.Append(c);
            if (stage == 0) Write(c.ToString());
        }

        void SignIn(string who, string secret)
        {
            IntPtr tok = IntPtr.Zero;
            int err = 0;
            string name = who, domain = ".";
            int slash = who.IndexOf('\\');
            if (slash > 0)
            {
                domain = who.Substring(0, slash);
                name = who.Substring(slash + 1);
                if (!Native.LogonUser(name, domain, secret, 2, 0, out tok)) err = Marshal.GetLastWin32Error();
            }
            else if (who.IndexOf('@') > 0)
            {
                if (!Native.LogonUser(who, null, secret, 2, 0, out tok)) err = Marshal.GetLastWin32Error();
            }
            else
            {
                // A plain name on a domain member means the domain's account,
                // as at the sign-in screen; then this computer's own.
                bool ok = false;
                if (Host.DomainDns.Length > 0)
                {
                    ok = Native.LogonUser(who + "@" + Host.DomainDns, null, secret, 2, 0, out tok);
                    if (!ok) err = Marshal.GetLastWin32Error();
                }
                if (!ok && (err == 0 || err == 1326 || err == 1317))
                {
                    ok = Native.LogonUser(who, ".", secret, 2, 0, out tok);
                    err = ok ? 0 : Marshal.GetLastWin32Error();
                }
            }
            secret = null;
            if (err != 0 || tok == IntPtr.Zero)
            {
                Host.Log("session " + sid + ": sign-in as " + who + " refused (" + err + ")");
                Refused(new Win32Exception(err).Message);
                return;
            }
            if (admin)
            {
                IntPtr full = Native.Elevated(tok);
                if (full == IntPtr.Zero)
                {
                    Native.CloseHandle(tok);
                    Refused(who + " is not an administrator on " + Host.Computer + ". Sign in with an administrator's account to run as administrator.");
                    return;
                }
                if (full != tok) { Native.CloseHandle(tok); tok = full; }
            }
            Host.Log("session " + sid + ": signed in as " + who + (admin ? " (administrator)" : ""));
            Launch(tok, name);
        }

        void Refused(string why)
        {
            lock (gate)
            {
                if (stage == 4) return;
                Write(why.Trim() + "\r\n\r\n");
                tries++;
                if (tries >= 5)
                {
                    Write("Too many tries.\r\n");
                    stage = 4;
                    Host.Send("EXIT " + sid + " 1");
                    Host.Forget(sid);
                    return;
                }
                stage = 0;
                Prompt();
            }
        }

        void Launch(IntPtr tok, string userName)
        {
            lock (gate)
            {
                if (stage == 4) { if (tok != IntPtr.Zero) Native.CloseHandle(tok); return; }
                try
                {
                    token = tok;
                    string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    string exe = shell == "cmd"
                        ? Path.Combine(sys, "cmd.exe")
                        : Path.Combine(sys, "WindowsPowerShell\\v1.0\\powershell.exe");
                    string cwd;
                    if (tok != IntPtr.Zero)
                    {
                        profile = Native.LoadProfile(tok, userName);
                        env = Native.Environment(tok);
                        cwd = admin ? sys : Native.ProfileDir(tok);
                    }
                    else
                    {
                        cwd = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    }
                    if (string.IsNullOrEmpty(cwd) || !Directory.Exists(cwd)) cwd = sys;

                    // The pseudoconsole draws as if on a blank screen: the
                    // sign-in prompt goes, as it does once a remote console signs in.
                    Write("\x1b[H\x1b[2J\x1b[3J");

                    SafeFileHandle inRead, inWrite, outRead, outWrite;
                    Native.Pipe(out inRead, out inWrite);
                    Native.Pipe(out outRead, out outWrite);
                    hpc = Native.CreatePty(cols, rows, inRead, outWrite);
                    // the pseudoconsole holds its own copies of these ends
                    inRead.Dispose();
                    outWrite.Dispose();
                    input = new FileStream(inWrite, FileAccess.Write, 1);
                    output = new FileStream(outRead, FileAccess.Read, 1);

                    pump = new Thread(Pump);
                    pump.IsBackground = true;
                    pump.Start();

                    string title = (admin ? "Administrator: " : "")
                        + (shell == "cmd" ? "Command Prompt" : "Windows PowerShell");
                    hProcess = Native.Spawn(tok, "\"" + exe + "\"", cwd, env, hpc, title);
                    stage = 3;
                    Host.Log("session " + sid + ": " + exe + " started");

                    Thread waiter = new Thread(Wait);
                    waiter.IsBackground = true;
                    waiter.Start();
                }
                catch (Exception ex)
                {
                    Host.Log("session " + sid + ": could not start " + shell + ": " + ex.Message);
                    Write("\r\nWindows could not start " + (shell == "cmd" ? "cmd.exe" : "powershell.exe") + ": " + ex.Message + "\r\n");
                    stage = 4;
                    Finish(1);
                }
            }
        }

        void Pump()
        {
            byte[] buf = new byte[4096];
            try
            {
                while (true)
                {
                    int n = output.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    Host.SendOut(sid, buf, n);
                }
            }
            catch (Exception) { }
        }

        void Wait()
        {
            Native.WaitForSingleObject(hProcess, 0xFFFFFFFF);
            uint code = 0;
            Native.GetExitCodeProcess(hProcess, out code);
            lock (gate) { stage = 4; }
            Finish((int)code);
        }

        public void Resize(short c, short r)
        {
            lock (gate)
            {
                cols = (short)Math.Max(20, Math.Min(500, (int)c));
                rows = (short)Math.Max(5, Math.Min(300, (int)r));
                if (hpc != IntPtr.Zero) Native.ResizePty(hpc, cols, rows);
            }
        }

        // The window was closed on the desktop: the console goes away, and
        // with it the programs attached to it, as when a console window closes.
        public void Close()
        {
            bool running;
            lock (gate)
            {
                running = stage == 3;
                stage = 4;
            }
            if (!running) Finish(0);
            else ThreadPool.QueueUserWorkItem(delegate { ClosePty(); });
        }

        void ClosePty()
        {
            IntPtr h;
            lock (gate) { h = hpc; hpc = IntPtr.Zero; }
            if (h != IntPtr.Zero) Native.ClosePseudoConsole(h);
        }

        void Finish(int code)
        {
            // The output drains before the pseudoconsole closes, or closing
            // it blocks on older builds of Windows.
            ClosePty();
            lock (gate)
            {
                if (exitSent) return;
                exitSent = true;
            }
            if (pump != null) pump.Join(3000);
            Host.Send("EXIT " + sid + " " + code);
            Host.Forget(sid);
            try { if (input != null) input.Dispose(); } catch (Exception) { }
            try { if (output != null) output.Dispose(); } catch (Exception) { }
            if (hProcess != IntPtr.Zero) { Native.CloseHandle(hProcess); hProcess = IntPtr.Zero; }
            if (env != IntPtr.Zero) { Native.DestroyEnvironmentBlock(env); env = IntPtr.Zero; }
            if (profile != IntPtr.Zero) { Native.UnloadUserProfile(token, profile); profile = IntPtr.Zero; }
            if (token != IntPtr.Zero) { Native.CloseHandle(token); token = IntPtr.Zero; }
        }
    }

    public static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct COORD { public short X; public short Y; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROFILEINFO
        {
            public int dwSize;
            public int dwFlags;
            public string lpUserName;
            public string lpProfilePath;
            public string lpDefaultPath;
            public string lpServerName;
            public string lpPolicyPath;
            public IntPtr hProfile;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint Low; public int High; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES { public int Count; public LUID Luid; public int Attributes; }

        const int EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const int STARTF_USESTDHANDLES = 0x00000100;
        static readonly IntPtr PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = (IntPtr)0x00020016;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int CreatePseudoConsole(COORD size, SafeFileHandle hInput, SafeFileHandle hOutput, uint flags, out IntPtr hpc);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int ResizePseudoConsole(IntPtr hpc, COORD size);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void ClosePseudoConsole(IntPtr hpc);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, IntPtr attrs, int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value, IntPtr size, IntPtr prev, IntPtr retSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUserW(IntPtr token, string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr h, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr token, int cls, out IntPtr info, int len, out int retLen);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr token, int cls, out int info, int len, out int retLen);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, int len, IntPtr prev, IntPtr retLen);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LoadUserProfile(IntPtr token, ref PROFILEINFO info);
        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool UnloadUserProfile(IntPtr token, IntPtr profile);
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);
        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool DestroyEnvironmentBlock(IntPtr env);
        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool GetUserProfileDirectory(IntPtr token, StringBuilder dir, ref int size);

        static Win32Exception Last(string what)
        {
            int e = Marshal.GetLastWin32Error();
            return new Win32Exception(e, what + ": " + new Win32Exception(e).Message);
        }

        // SYSTEM holds these but has them switched off: starting a process
        // with another account's token and loading its profile need them on.
        public static void EnablePrivileges()
        {
            IntPtr tok;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out tok)) return;
            foreach (string p in new string[] { "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege",
                                                "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege" })
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, p, out luid)) continue;
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.Count = 1;
                tp.Luid = luid;
                tp.Attributes = 2;   // SE_PRIVILEGE_ENABLED
                AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            CloseHandle(tok);
        }

        // The account's full token for "Run as administrator": the linked
        // token of a filtered administrator (UAC), the token itself when it
        // is already elevated, IntPtr.Zero for an account that is no
        // administrator.
        public static IntPtr Elevated(IntPtr token)
        {
            int type, len;
            if (GetTokenInformation(token, 18, out type, 4, out len) && type == 3)
            {
                IntPtr linked;
                if (GetTokenInformation(token, 19, out linked, IntPtr.Size, out len)) return linked;
                return IntPtr.Zero;
            }
            int elevated;
            if (GetTokenInformation(token, 20, out elevated, 4, out len) && elevated != 0) return token;
            return IntPtr.Zero;
        }

        public static IntPtr LoadProfile(IntPtr token, string user)
        {
            PROFILEINFO pi = new PROFILEINFO();
            pi.dwSize = Marshal.SizeOf(typeof(PROFILEINFO));
            pi.dwFlags = 1;   // PI_NOUI
            pi.lpUserName = user;
            if (!LoadUserProfile(token, ref pi)) throw Last("LoadUserProfile");
            return pi.hProfile;
        }

        public static IntPtr Environment(IntPtr token)
        {
            IntPtr env;
            if (!CreateEnvironmentBlock(out env, token, false)) throw Last("CreateEnvironmentBlock");
            return env;
        }

        public static string ProfileDir(IntPtr token)
        {
            int size = 260;
            StringBuilder sb = new StringBuilder(size);
            if (!GetUserProfileDirectory(token, sb, ref size)) return "";
            return sb.ToString();
        }

        public static void Pipe(out SafeFileHandle read, out SafeFileHandle write)
        {
            if (!CreatePipe(out read, out write, IntPtr.Zero, 0)) throw Last("CreatePipe");
        }

        public static IntPtr CreatePty(short cols, short rows, SafeFileHandle input, SafeFileHandle output)
        {
            COORD size = new COORD();
            size.X = cols;
            size.Y = rows;
            IntPtr hpc;
            int hr;
            try
            {
                hr = CreatePseudoConsole(size, input, output, 0, out hpc);
            }
            catch (EntryPointNotFoundException)
            {
                throw new InvalidOperationException("this version of Windows has no pseudoconsole (Windows 10 1809 or Windows Server 2019 and later have one)");
            }
            if (hr != 0) throw new Win32Exception(hr, "CreatePseudoConsole failed (0x" + hr.ToString("X8") + ")");
            return hpc;
        }

        public static void ResizePty(IntPtr hpc, short cols, short rows)
        {
            COORD size = new COORD();
            size.X = cols;
            size.Y = rows;
            ResizePseudoConsole(hpc, size);
        }

        // Starts the shell in the pseudoconsole, as the signed-in account
        // (token) or, in the tests, as this process's own.
        public static IntPtr Spawn(IntPtr token, string cmdline, string cwd, IntPtr env, IntPtr hpc, string title)
        {
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            IntPtr list = Marshal.AllocHGlobal(size);
            try
            {
                if (!InitializeProcThreadAttributeList(list, 1, 0, ref size)) throw Last("InitializeProcThreadAttributeList");
                if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                    throw Last("UpdateProcThreadAttribute");
                STARTUPINFOEX si = new STARTUPINFOEX();
                si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                // No standard handles of this host's own: the shell's console
                // is the pseudoconsole and nothing else.
                si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                si.StartupInfo.lpTitle = title;
                // "": Windows connects the account to a window station of
                // its own logon session, not to this service's.
                si.StartupInfo.lpDesktop = token != IntPtr.Zero ? "" : null;
                si.lpAttributeList = list;
                PROCESS_INFORMATION pi;
                int flags = EXTENDED_STARTUPINFO_PRESENT | (env != IntPtr.Zero ? CREATE_UNICODE_ENVIRONMENT : 0);
                StringBuilder cmd = new StringBuilder(cmdline);
                bool ok = token != IntPtr.Zero
                    ? CreateProcessAsUserW(token, null, cmd, IntPtr.Zero, IntPtr.Zero, false, flags, env, cwd, ref si, out pi)
                    : CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, flags, env, cwd, ref si, out pi);
                if (!ok) throw Last("CreateProcess");
                CloseHandle(pi.hThread);
                return pi.hProcess;
            }
            finally
            {
                DeleteProcThreadAttributeList(list);
                Marshal.FreeHGlobal(list);
            }
        }
    }
}
