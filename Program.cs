using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

namespace NetworkCorner
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--self-test")
            {
                Environment.Exit(SelfTests.Run());
                return;
            }

            if (args.Length == 2 && args[0] == "--apply-file")
            {
                Environment.Exit(NetworkChanger.ApplyFromFile(args[1]));
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    internal sealed class NetworkProfile
    {
        public string Name { get; set; }
        public string Address { get; set; }
        public string Mask { get; set; }
        public string Gateway { get; set; }
        public string Dns1 { get; set; }
        public string Dns2 { get; set; }
    }

    internal sealed class AppPreferences
    {
        public int MonitorIndex { get; set; }
        public int CornerIndex { get; set; }
        public bool FullHeight { get; set; }
        public bool HideDownAdapters { get; set; }
        public int SelectedTabIndex { get; set; }
        public int WindowWidth { get; set; }
        public int WindowHeight { get; set; }
    }

    internal sealed class ChangeRequest
    {
        public string Adapter { get; set; }
        public string Operation { get; set; }
        public bool Dhcp { get; set; }
        public string Address { get; set; }
        public string Mask { get; set; }
        public string Gateway { get; set; }
        public string Dns1 { get; set; }
        public string Dns2 { get; set; }
    }

    internal sealed class AdapterInfo
    {
        public string Id;
        public string Name;
        public string Kind;
        public string Status;
        public string Address;
        public string Mask;
        public string Gateway;
        public string Dns1;
        public string Dns2;
        public string Assignment;

        public override string ToString() { return Kind + " — " + Name; }
    }

    internal sealed class ScanNetworkOption
    {
        public string Label;
        public string Target;
        public bool IsManual;
        public override string ToString() { return Label; }
    }

    internal static class NetworkReader
    {
        public static List<AdapterInfo> GetAdapters()
        {
            var result = new List<AdapterInfo>();
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!IsUseful(nic)) continue;
                var item = new AdapterInfo();
                item.Id = nic.Id;
                item.Name = nic.Name;
                item.Kind = FriendlyKind(nic.NetworkInterfaceType);
                item.Status = nic.OperationalStatus == OperationalStatus.Up ? "Connected" : nic.OperationalStatus.ToString();
                item.Assignment = ReadAssignmentMode(nic.Id);
                try
                {
                    IPInterfaceProperties props = nic.GetIPProperties();
                    UnicastIPAddressInformation ipv4 = props.UnicastAddresses.FirstOrDefault(x => x.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (ipv4 != null)
                    {
                        item.Address = ipv4.Address.ToString();
                        item.Mask = ipv4.IPv4Mask == null ? "" : ipv4.IPv4Mask.ToString();
                    }
                    GatewayIPAddressInformation gateway = props.GatewayAddresses.FirstOrDefault(x => x.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    item.Gateway = gateway == null ? "" : gateway.Address.ToString();
                    string[] dns = props.DnsAddresses.Where(x => x.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(x => x.ToString()).ToArray();
                    item.Dns1 = dns.Length > 0 ? dns[0] : "";
                    item.Dns2 = dns.Length > 1 ? dns[1] : "";
                }
                catch { }
                result.Add(item);
            }
            return result.OrderBy(x => x.Kind).ThenBy(x => x.Name).ToList();
        }

        private static string ReadAssignmentMode(string adapterId)
        {
            try
            {
                string keyPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + adapterId;
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key == null) return "Unknown";
                    object value = key.GetValue("EnableDHCP");
                    if (value == null) return "Unknown";
                    return Convert.ToInt32(value) == 1 ? "Dynamic / DHCP" : "Static";
                }
            }
            catch { return "Unknown"; }
        }

        private static bool IsUseful(NetworkInterface nic)
        {
            NetworkInterfaceType t = nic.NetworkInterfaceType;
            return t == NetworkInterfaceType.Ethernet ||
                   t == NetworkInterfaceType.GigabitEthernet ||
                   t == NetworkInterfaceType.FastEthernetFx ||
                   t == NetworkInterfaceType.FastEthernetT ||
                   t == NetworkInterfaceType.Wireless80211;
        }

        private static string FriendlyKind(NetworkInterfaceType type)
        {
            return type == NetworkInterfaceType.Wireless80211 ? "Wi-Fi" : "Ethernet";
        }
    }

    internal static class RequestValidator
    {
        public static string Validate(ChangeRequest request)
        {
            if (request == null) return "The change request is missing.";
            if (request.Operation == "flushdns") return null;
            if (String.IsNullOrWhiteSpace(request.Adapter)) return "Choose a network adapter.";
            if (request.Adapter.IndexOf('"') >= 0 || request.Adapter.IndexOf('\r') >= 0 || request.Adapter.IndexOf('\n') >= 0)
                return "The adapter name contains unsupported characters.";
            if (!String.IsNullOrWhiteSpace(request.Operation))
            {
                if (request.Operation == "release" || request.Operation == "renew") return null;
                return "The requested IP operation is not supported.";
            }
            if (request.Dhcp) return null;
            if (!IsIpv4(request.Address)) return "Enter a valid IPv4 address.";
            if (!IsValidMask(request.Mask)) return "Enter a valid contiguous subnet mask (for example 255.255.255.0).";
            if (!IsOptionalIpv4(request.Gateway)) return "Enter a valid gateway, or leave it blank.";
            if (!IsOptionalIpv4(request.Dns1)) return "Enter a valid primary DNS address, or leave it blank.";
            if (!IsOptionalIpv4(request.Dns2)) return "Enter a valid secondary DNS address, or leave it blank.";
            if (!String.IsNullOrWhiteSpace(request.Dns2) && String.IsNullOrWhiteSpace(request.Dns1))
                return "Enter a primary DNS address before adding a secondary DNS address.";
            return null;
        }

        public static bool IsIpv4(string value)
        {
            IPAddress parsed;
            return IPAddress.TryParse((value ?? "").Trim(), out parsed) && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        }

        private static bool IsOptionalIpv4(string value)
        {
            return String.IsNullOrWhiteSpace(value) || IsIpv4(value);
        }

        private static bool IsValidMask(string value)
        {
            if (!IsIpv4(value)) return false;
            byte[] bytes = IPAddress.Parse(value.Trim()).GetAddressBytes();
            uint mask = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            bool sawZero = false;
            for (int bit = 31; bit >= 0; bit--)
            {
                bool one = (mask & (1u << bit)) != 0;
                if (!one) sawZero = true;
                else if (sawZero) return false;
            }
            return mask != 0;
        }
    }

    internal static class NetworkChanger
    {
        public static int ApplyFromFile(string path)
        {
            try
            {
                string json = File.ReadAllText(path, Encoding.UTF8);
                var request = new JavaScriptSerializer().Deserialize<ChangeRequest>(json);
                string validation = RequestValidator.Validate(request);
                if (validation != null) throw new InvalidOperationException(validation);
                Apply(request);
                string success = request.Operation == "release" ? "The adapter's DHCP lease was released." :
                                 request.Operation == "renew" ? "The adapter's DHCP lease was renewed." :
                                 request.Operation == "flushdns" ? "The Windows DNS resolver cache was flushed." :
                                 request.Dhcp ? "DHCP is now enabled." : "The static network settings were applied.";
                MessageBox.Show(success, "Network Corner", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return 0;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Network change failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }

        public static List<string> BuildCommands(ChangeRequest r)
        {
            string name = Quote(r.Adapter);
            var commands = new List<string>();
            if (r.Dhcp)
            {
                commands.Add("interface ipv4 set address name=" + name + " source=dhcp");
                commands.Add("interface ipv4 set dnsservers name=" + name + " source=dhcp");
                return commands;
            }

            string gateway = String.IsNullOrWhiteSpace(r.Gateway) ? "none" : r.Gateway.Trim();
            commands.Add("interface ipv4 set address name=" + name + " source=static address=" + r.Address.Trim() + " mask=" + r.Mask.Trim() + " gateway=" + gateway + " store=persistent");
            if (!String.IsNullOrWhiteSpace(r.Dns1))
            {
                commands.Add("interface ipv4 set dnsservers name=" + name + " source=static address=" + r.Dns1.Trim() + " register=primary validate=no");
                if (!String.IsNullOrWhiteSpace(r.Dns2))
                    commands.Add("interface ipv4 add dnsservers name=" + name + " address=" + r.Dns2.Trim() + " index=2 validate=no");
            }
            return commands;
        }

        public static string BuildIpconfigArguments(ChangeRequest request)
        {
            if (request.Operation == "flushdns") return "/flushdns";
            if (request.Operation != "release" && request.Operation != "renew")
                throw new ArgumentException("Unsupported IP operation.");
            return "/" + request.Operation + " " + Quote(request.Adapter);
        }

        private static void Apply(ChangeRequest request)
        {
            if (!IsAdministrator()) throw new InvalidOperationException("Administrator permission is required to change network settings.");
            if (!String.IsNullOrWhiteSpace(request.Operation))
            {
                RunIpconfig(BuildIpconfigArguments(request));
                return;
            }
            foreach (string command in BuildCommands(request)) RunNetsh(command);
        }

        private static void RunIpconfig(string arguments)
        {
            var psi = new ProcessStartInfo("ipconfig.exe", arguments);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process process = Process.Start(psi))
            {
                string stdout = process.StandardOutput.ReadToEnd();
                string stderr = process.StandardError.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode != 0)
                    throw new InvalidOperationException("Windows rejected the IP operation.\r\n\r\n" + FirstNonEmpty(stderr, stdout));
            }
        }

        private static void RunNetsh(string arguments)
        {
            var psi = new ProcessStartInfo("netsh.exe", arguments);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process process = Process.Start(psi))
            {
                string stdout = process.StandardOutput.ReadToEnd();
                string stderr = process.StandardError.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode != 0)
                    throw new InvalidOperationException("Windows rejected the network change.\r\n\r\n" + FirstNonEmpty(stderr, stdout));
            }
        }

        private static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static string Quote(string value) { return "\"" + value + "\""; }
        private static string FirstNonEmpty(string a, string b) { return !String.IsNullOrWhiteSpace(a) ? a.Trim() : b.Trim(); }
    }

    internal static class NmapSupport
    {
        public static string FindExecutable()
        {
            string[] candidates =
            {
                @"C:\Program Files (x86)\Nmap\nmap.exe",
                @"C:\Program Files\Nmap\nmap.exe"
            };
            foreach (string candidate in candidates) if (File.Exists(candidate)) return candidate;
            string path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string folder in path.Split(Path.PathSeparator))
            {
                try
                {
                    string candidate = Path.Combine(folder.Trim(), "nmap.exe");
                    if (File.Exists(candidate)) return candidate;
                }
                catch { }
            }
            return null;
        }

        public static string ValidateTarget(string target)
        {
            if (String.IsNullOrWhiteSpace(target)) return "Enter a scan target.";
            target = target.Trim();
            if (target.Length > 255) return "The scan target is too long.";
            if (target.StartsWith("-")) return "The scan target cannot start with a dash.";
            foreach (char c in target)
            {
                if (!(Char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_' || c == ':' || c == '/' || c == '%'))
                    return "Use a hostname, IPv4/IPv6 address, or CIDR range without spaces.";
            }
            return null;
        }

        public static string ArgumentsFor(int presetIndex, string target, string interfaceName = null)
        {
            string options;
            switch (presetIndex)
            {
                case 0: options = "-sn --reason"; break;
                case 1: options = "-sT --top-ports 100 --reason -T4"; break;
                case 2: options = "-sT --reason -T4"; break;
                case 3: options = "-sT -sV --top-ports 100 --reason -T4"; break;
                default: throw new ArgumentOutOfRangeException("presetIndex");
            }
            if (!String.IsNullOrWhiteSpace(interfaceName)) options += " -e " + interfaceName.Trim();
            return options + " " + target.Trim();
        }

        public static Dictionary<string, string> GetInterfaceMap(string executable)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (String.IsNullOrWhiteSpace(executable) || !File.Exists(executable)) return result;
            var psi = new ProcessStartInfo(executable, "--iflist");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process process = Process.Start(psi))
            {
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return ParseInterfaceMap(output);
            }
        }

        public static Dictionary<string, string> ParseInterfaceMap(string output)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string rawLine in (output ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                int marker = rawLine.IndexOf(@"\Device\NPF_{", StringComparison.OrdinalIgnoreCase);
                if (marker < 0) continue;
                string[] parts = rawLine.Trim().Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                int open = rawLine.IndexOf('{', marker);
                int close = rawLine.IndexOf('}', open + 1);
                if (open < 0 || close < 0) continue;
                string id = rawLine.Substring(open + 1, close - open - 1);
                if (!result.ContainsKey(id)) result.Add(id, parts[0]);
            }
            return result;
        }

        public static string NetworkTarget(string address, string mask)
        {
            if (!RequestValidator.IsIpv4(address) || !RequestValidator.IsIpv4(mask)) return null;
            byte[] addressBytes = IPAddress.Parse(address).GetAddressBytes();
            byte[] maskBytes = IPAddress.Parse(mask).GetAddressBytes();
            byte[] networkBytes = new byte[4];
            int prefix = 0;
            bool sawZero = false;
            for (int i = 0; i < 4; i++)
            {
                networkBytes[i] = (byte)(addressBytes[i] & maskBytes[i]);
                for (int bit = 7; bit >= 0; bit--)
                {
                    bool one = (maskBytes[i] & (1 << bit)) != 0;
                    if (one && sawZero) return null;
                    if (one) prefix++; else sawZero = true;
                }
            }
            if (prefix == 0) return null;
            return new IPAddress(networkBytes).ToString() + "/" + prefix;
        }
    }

    internal static class PingSupport
    {
        public static string ValidateTarget(string target)
        {
            if (String.IsNullOrWhiteSpace(target)) return "Enter a ping target.";
            target = target.Trim();
            if (target.Length > 255) return "The ping target is too long.";
            if (target.StartsWith("-") || target.Contains("/")) return "Enter one hostname or IP address, not a network range.";
            foreach (char c in target)
            {
                if (!(Char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_' || c == ':' || c == '%'))
                    return "Use a hostname or IP address without spaces.";
            }
            return null;
        }

        public static string ArgumentsFor(string target, bool continuous, string sourceAddress = null)
        {
            string arguments = continuous ? "-t" : "-n 4";
            if (!String.IsNullOrWhiteSpace(sourceAddress)) arguments += " -S " + sourceAddress.Trim();
            return arguments + " " + target.Trim();
        }
    }

    internal static class ConnectionSupport
    {
        public static string ValidateHost(string host)
        {
            string validation = PingSupport.ValidateTarget(host);
            return validation == null ? null : validation.Replace("ping target", "host").Replace("Ping target", "Host");
        }

        public static string ValidateUsername(string username)
        {
            if (String.IsNullOrWhiteSpace(username)) return null;
            foreach (char c in username.Trim())
            {
                if (!(Char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_'))
                    return "The SSH username contains unsupported characters.";
            }
            return null;
        }

        public static string BuildClientArguments(bool ssh, string host, int port, string username, string sourceAddress = null)
        {
            if (ssh)
            {
                string destination = String.IsNullOrWhiteSpace(username) ? host.Trim() : username.Trim() + "@" + host.Trim();
                string bind = String.IsNullOrWhiteSpace(sourceAddress) ? "" : "-b " + sourceAddress.Trim() + " ";
                return bind + "-p " + port + " " + destination;
            }
            return host.Trim() + " " + port;
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly Color Back = Color.FromArgb(20, 25, 32);
        private readonly Color Panel = Color.FromArgb(30, 37, 47);
        private readonly Color Muted = Color.FromArgb(157, 170, 187);
        private readonly Color Accent = Color.FromArgb(51, 182, 161);
        private readonly Font summaryRegularFont = new Font("Consolas", 9F, FontStyle.Regular);
        private readonly Font summaryBoldFont = new Font("Consolas", 9F, FontStyle.Bold);
        private readonly TabControl mainTabs = new TabControl();
        private readonly ComboBox adapterBox = new ComboBox();
        private readonly ComboBox profileBox = new ComboBox();
        private readonly ComboBox screenBox = new ComboBox();
        private readonly ComboBox cornerBox = new ComboBox();
        private readonly CheckBox fullHeightCheck = new CheckBox();
        private readonly CheckBox hideDownCheck = new CheckBox();
        private readonly TextBox addressBox = new TextBox();
        private readonly TextBox maskBox = new TextBox();
        private readonly TextBox gatewayBox = new TextBox();
        private readonly TextBox dns1Box = new TextBox();
        private readonly TextBox dns2Box = new TextBox();
        private readonly RichTextBox summaryBox = new RichTextBox();
        private readonly TextBox scanTargetBox = new TextBox();
        private readonly ComboBox scanAdapterBox = new ComboBox();
        private readonly ComboBox scanNetworkBox = new ComboBox();
        private readonly ComboBox scanPresetBox = new ComboBox();
        private readonly RichTextBox scanOutputBox = new RichTextBox();
        private readonly Label scanStatusLabel = new Label();
        private Button scanStartButton;
        private Button scanCancelButton;
        private readonly TextBox pingTargetBox = new TextBox();
        private readonly ComboBox pingAdapterBox = new ComboBox();
        private readonly ComboBox pingTargetModeBox = new ComboBox();
        private readonly CheckBox continuousPingCheck = new CheckBox();
        private readonly RichTextBox pingOutputBox = new RichTextBox();
        private readonly Label pingStatusLabel = new Label();
        private Button pingStartButton;
        private Button pingStopButton;
        private readonly ComboBox connectionProtocolBox = new ComboBox();
        private readonly ComboBox connectionAdapterBox = new ComboBox();
        private readonly ComboBox connectionTargetModeBox = new ComboBox();
        private readonly TextBox connectionHostBox = new TextBox();
        private readonly TextBox connectionUsernameBox = new TextBox();
        private readonly NumericUpDown connectionPortBox = new NumericUpDown();
        private readonly Label connectionStatusLabel = new Label();
        private readonly TextBox diagnosticsTargetBox = new TextBox();
        private readonly NumericUpDown diagnosticsPortBox = new NumericUpDown();
        private readonly RichTextBox diagnosticsOutputBox = new RichTextBox();
        private readonly Label diagnosticsStatusLabel = new Label();
        private Button diagnosticsStopButton;
        private Button releaseIpButton;
        private Button renewIpButton;
        private readonly Label updatedLabel = new Label();
        private readonly System.Windows.Forms.Timer refreshTimer = new System.Windows.Forms.Timer();
        private List<AdapterInfo> adapters = new List<AdapterInfo>();
        private List<NetworkProfile> profiles = new List<NetworkProfile>();
        private bool loading;
        private int normalHeight;
        private Process currentScan;
        private Process currentPing;
        private Process currentDiagnostic;
        private bool diagnosticBusy;
        private Dictionary<string, string> nmapInterfaces = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly string profilePath;
        private readonly string preferencesPath;

        public MainForm()
        {
            profilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkCorner", "profiles.json");
            preferencesPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkCorner", "settings.json");
            Text = "Network Corner";
            ClientSize = new Size(410, 780);
            MinimumSize = new Size(390, 650);
            BackColor = Back;
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 9F);
            TopMost = true;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = true;
            MaximizeBox = false;
            StartPosition = FormStartPosition.Manual;
            ShowInTaskbar = true;

            BuildUi();
            LoadProfiles();
            LoadScreens();
            LoadPreferences();
            RefreshAdapters(true);
            refreshTimer.Interval = 5000;
            refreshTimer.Tick += delegate { RefreshAdapters(false); };
            refreshTimer.Start();
            Shown += delegate { normalHeight = Height; DockToCorner(); };
            ResizeEnd += delegate { if (!fullHeightCheck.Checked) normalHeight = Height; };
            FormClosed += delegate
            {
                if (currentScan != null && !currentScan.HasExited) currentScan.Kill();
                if (currentPing != null && !currentPing.HasExited) currentPing.Kill();
                if (currentDiagnostic != null && !currentDiagnostic.HasExited) currentDiagnostic.Kill();
                summaryRegularFont.Dispose();
                summaryBoldFont.Dispose();
            };
            FormClosing += delegate { SavePreferences(); };
        }

        private void BuildUi()
        {
            mainTabs.Dock = DockStyle.Fill;
            mainTabs.Appearance = TabAppearance.Normal;
            var networkTab = new TabPage("Network") { BackColor = Back, ForeColor = Color.White };
            var scanTab = new TabPage("Nmap Scan") { BackColor = Back, ForeColor = Color.White };
            var pingTab = new TabPage("Ping") { BackColor = Back, ForeColor = Color.White };
            var connectionTab = new TabPage("Telnet / SSH") { BackColor = Back, ForeColor = Color.White };
            var diagnosticsTab = new TabPage("Diagnostics") { BackColor = Back, ForeColor = Color.White };
            mainTabs.TabPages.Add(networkTab);
            mainTabs.TabPages.Add(scanTab);
            mainTabs.TabPages.Add(pingTab);
            mainTabs.TabPages.Add(connectionTab);
            mainTabs.TabPages.Add(diagnosticsTab);
            Controls.Add(mainTabs);

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(14), ColumnCount = 1, RowCount = 5, BackColor = Back };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 340));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 105));
            networkTab.Controls.Add(root);

            var titlePanel = new Panel { Dock = DockStyle.Fill };
            var title = new Label { Text = "NETWORK CORNER", Font = new Font("Segoe UI Semibold", 14F), AutoSize = true, Location = new Point(0, 2), ForeColor = Color.White };
            updatedLabel.Text = "Checking adapters…";
            updatedLabel.AutoSize = true;
            updatedLabel.Location = new Point(2, 29);
            updatedLabel.ForeColor = Muted;
            hideDownCheck.Text = "Hide down adapters";
            hideDownCheck.AutoSize = false;
            hideDownCheck.Width = 128;
            hideDownCheck.Dock = DockStyle.Right;
            hideDownCheck.ForeColor = Color.FromArgb(220, 228, 238);
            hideDownCheck.TextAlign = ContentAlignment.MiddleLeft;
            hideDownCheck.Checked = true;
            hideDownCheck.CheckedChanged += delegate { if (!loading) RefreshAdapters(true); };
            titlePanel.Controls.Add(title);
            titlePanel.Controls.Add(updatedLabel);
            titlePanel.Controls.Add(hideDownCheck);
            root.Controls.Add(titlePanel, 0, 0);

            var statusPanel = Card();
            summaryBox.Dock = DockStyle.Fill;
            summaryBox.ReadOnly = true;
            summaryBox.BorderStyle = BorderStyle.None;
            summaryBox.BackColor = Panel;
            summaryBox.ForeColor = Color.FromArgb(220, 228, 238);
            summaryBox.Font = summaryRegularFont;
            summaryBox.ScrollBars = RichTextBoxScrollBars.Vertical;
            summaryBox.DetectUrls = false;
            summaryBox.TabStop = false;
            statusPanel.Controls.Add(summaryBox);
            root.Controls.Add(statusPanel, 0, 1);

            var adapterPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 8, 0, 5) };
            adapterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 76));
            adapterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            adapterPanel.Controls.Add(FieldLabel("EDIT"), 0, 0);
            StyleCombo(adapterBox);
            adapterBox.Dock = DockStyle.Fill;
            adapterBox.SelectedIndexChanged += delegate { if (!loading) PopulateFields(); };
            adapterPanel.Controls.Add(adapterBox, 1, 0);
            root.Controls.Add(adapterPanel, 0, 2);

            var editor = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 9, Padding = new Padding(12), BackColor = Panel };
            editor.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 105));
            editor.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 9; i++) editor.RowStyles.Add(new RowStyle(SizeType.Percent, 11.111F));
            AddField(editor, 0, "IP address", addressBox);
            AddField(editor, 1, "Subnet mask", maskBox);
            AddField(editor, 2, "Gateway", gatewayBox);
            AddField(editor, 3, "Primary DNS", dns1Box);
            AddField(editor, 4, "Secondary DNS", dns2Box);

            StyleCombo(profileBox);
            profileBox.SelectedIndexChanged += delegate { if (!loading) LoadSelectedProfile(); };
            editor.Controls.Add(FieldLabel("PROFILE"), 0, 5);
            editor.Controls.Add(profileBox, 1, 5);

            var profileButtons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, Margin = new Padding(0) };
            profileButtons.Controls.Add(MakeButton("Save current", delegate { SaveProfile(); }, false, 112));
            profileButtons.Controls.Add(MakeButton("Delete", delegate { DeleteProfile(); }, false, 76));
            editor.Controls.Add(profileButtons, 1, 6);

            var location = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, Margin = new Padding(0) };
            StyleCombo(screenBox); screenBox.Width = 110;
            StyleCombo(cornerBox); cornerBox.Width = 108;
            cornerBox.Items.AddRange(new object[] { "Top right", "Top left", "Bottom right", "Bottom left" });
            cornerBox.SelectedIndex = 0;
            screenBox.SelectedIndexChanged += delegate { if (!loading) DockToCorner(); };
            cornerBox.SelectedIndexChanged += delegate { if (!loading) DockToCorner(); };
            location.Controls.Add(screenBox);
            location.Controls.Add(cornerBox);
            editor.Controls.Add(FieldLabel("POSITION"), 0, 7);
            editor.Controls.Add(location, 1, 7);

            fullHeightCheck.Text = "Stretch panel to full monitor height";
            fullHeightCheck.Dock = DockStyle.Fill;
            fullHeightCheck.ForeColor = Color.White;
            fullHeightCheck.CheckedChanged += delegate { if (!loading) DockToCorner(); };
            editor.Controls.Add(FieldLabel("DISPLAY"), 0, 8);
            editor.Controls.Add(fullHeightCheck, 1, 8);
            root.Controls.Add(editor, 0, 3);

            var actions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 2, Padding = new Padding(0, 8, 0, 0), BackColor = Back };
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 31));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 31));
            actions.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            actions.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            actions.Controls.Add(MakeButton("Apply static", delegate { Apply(false); }, true, 0), 0, 0);
            actions.Controls.Add(MakeButton("Use DHCP", delegate { Apply(true); }, false, 0), 1, 0);
            actions.Controls.Add(MakeButton("Refresh IP", delegate { RefreshAdapters(true); }, false, 0), 2, 0);
            releaseIpButton = MakeButton("Release IP", delegate { RunIpOperation("release"); }, false, 0);
            renewIpButton = MakeButton("Renew IP", delegate { RunIpOperation("renew"); }, false, 0);
            actions.Controls.Add(releaseIpButton, 0, 1);
            actions.Controls.Add(renewIpButton, 1, 1);
            root.Controls.Add(actions, 0, 4);

            BuildScanTab(scanTab);
            BuildPingTab(pingTab);
            BuildConnectionTab(connectionTab);
            BuildDiagnosticsTab(diagnosticsTab);
        }

        private void BuildScanTab(TabPage scanTab)
        {
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(14), ColumnCount = 1, RowCount = 7, BackColor = Back };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 55));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            scanTab.Controls.Add(layout);

            var heading = new Panel { Dock = DockStyle.Fill };
            heading.Controls.Add(new Label { Text = "NMAP SCANNER", Font = new Font("Segoe UI Semibold", 14F), AutoSize = true, Location = new Point(0, 2), ForeColor = Color.White });
            scanStatusLabel.Text = File.Exists(NmapSupport.FindExecutable()) ? "Ready • Nmap detected" : "Nmap was not found";
            scanStatusLabel.AutoSize = true;
            scanStatusLabel.Location = new Point(2, 31);
            scanStatusLabel.ForeColor = Muted;
            heading.Controls.Add(scanStatusLabel);
            layout.Controls.Add(heading, 0, 0);

            var adapterRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 6, 0, 6) };
            adapterRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            adapterRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            adapterRow.Controls.Add(FieldLabel("ADAPTER"), 0, 0);
            StyleCombo(scanAdapterBox);
            scanAdapterBox.Dock = DockStyle.Fill;
            scanAdapterBox.SelectedIndexChanged += delegate { if (!loading) PopulateScanNetworks(null, false, true); };
            adapterRow.Controls.Add(scanAdapterBox, 1, 0);
            layout.Controls.Add(adapterRow, 0, 1);

            var networkRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 6, 0, 6) };
            networkRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            networkRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            networkRow.Controls.Add(FieldLabel("TARGET MODE"), 0, 0);
            StyleCombo(scanNetworkBox);
            scanNetworkBox.Dock = DockStyle.Fill;
            scanNetworkBox.SelectedIndexChanged += delegate
            {
                if (loading) return;
                ScanNetworkOption option = scanNetworkBox.SelectedItem as ScanNetworkOption;
                if (option != null && !String.IsNullOrWhiteSpace(option.Target))
                {
                    loading = true;
                    scanTargetBox.Text = option.Target;
                    loading = false;
                }
            };
            networkRow.Controls.Add(scanNetworkBox, 1, 0);
            layout.Controls.Add(networkRow, 0, 2);

            var targetRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 6, 0, 6) };
            targetRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            targetRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            targetRow.Controls.Add(FieldLabel("TARGET"), 0, 0);
            scanTargetBox.Dock = DockStyle.Fill;
            scanTargetBox.BorderStyle = BorderStyle.FixedSingle;
            scanTargetBox.BackColor = Color.FromArgb(42, 50, 62);
            scanTargetBox.ForeColor = Color.White;
            scanTargetBox.Text = "192.168.1.0/24";
            scanTargetBox.TextChanged += delegate
            {
                if (loading || scanNetworkBox.SelectedIndex < 0) return;
                ScanNetworkOption option = scanNetworkBox.SelectedItem as ScanNetworkOption;
                if (option != null && !String.IsNullOrWhiteSpace(option.Target) && !String.Equals(option.Target, scanTargetBox.Text.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    for (int i = 0; i < scanNetworkBox.Items.Count; i++)
                    {
                        ScanNetworkOption candidate = scanNetworkBox.Items[i] as ScanNetworkOption;
                        if (candidate != null && candidate.IsManual) { scanNetworkBox.SelectedIndex = i; break; }
                    }
                }
            };
            targetRow.Controls.Add(scanTargetBox, 1, 0);
            layout.Controls.Add(targetRow, 0, 3);

            var presetRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 6, 0, 6) };
            presetRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            presetRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            presetRow.Controls.Add(FieldLabel("SCAN TYPE"), 0, 0);
            StyleCombo(scanPresetBox);
            scanPresetBox.Dock = DockStyle.Fill;
            scanPresetBox.Items.AddRange(new object[] { "Discover devices", "Quick ports", "Standard ports", "Services + versions" });
            scanPresetBox.SelectedIndex = 0;
            presetRow.Controls.Add(scanPresetBox, 1, 0);
            layout.Controls.Add(presetRow, 0, 4);

            var buttons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, BackColor = Back, Padding = new Padding(0, 7, 0, 7) };
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28));
            scanStartButton = MakeButton("Start scan", delegate { StartScan(); }, true, 0);
            scanCancelButton = MakeButton("Cancel", delegate { CancelScan(); }, false, 0);
            scanCancelButton.Enabled = false;
            buttons.Controls.Add(scanStartButton, 0, 0);
            buttons.Controls.Add(scanCancelButton, 1, 0);
            buttons.Controls.Add(MakeButton("Use gateway", delegate { UseGatewayTarget(); }, false, 0), 2, 0);
            layout.Controls.Add(buttons, 0, 5);

            var outputPanel = Card();
            scanOutputBox.Dock = DockStyle.Fill;
            scanOutputBox.ReadOnly = true;
            scanOutputBox.BackColor = Color.FromArgb(15, 20, 26);
            scanOutputBox.ForeColor = Color.FromArgb(214, 225, 235);
            scanOutputBox.BorderStyle = BorderStyle.None;
            scanOutputBox.Font = summaryRegularFont;
            scanOutputBox.WordWrap = false;
            scanOutputBox.ScrollBars = RichTextBoxScrollBars.Both;
            scanOutputBox.DetectUrls = false;
            scanOutputBox.Text = "Enter a hostname, IPv4 address, or CIDR range, then choose a scan type.\r\nOnly scan networks and devices you are authorised to test.";
            outputPanel.Controls.Add(scanOutputBox);
            layout.Controls.Add(outputPanel, 0, 6);
        }

        private void BuildPingTab(TabPage pingTab)
        {
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(14), ColumnCount = 1, RowCount = 7, BackColor = Back };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 55));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            pingTab.Controls.Add(layout);

            var heading = new Panel { Dock = DockStyle.Fill };
            heading.Controls.Add(new Label { Text = "PING MONITOR", Font = new Font("Segoe UI Semibold", 14F), AutoSize = true, Location = new Point(0, 2), ForeColor = Color.White });
            pingStatusLabel.Text = "Ready";
            pingStatusLabel.AutoSize = true;
            pingStatusLabel.Location = new Point(2, 31);
            pingStatusLabel.ForeColor = Muted;
            heading.Controls.Add(pingStatusLabel);
            layout.Controls.Add(heading, 0, 0);

            var adapterRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 6, 0, 6) };
            adapterRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            adapterRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            adapterRow.Controls.Add(FieldLabel("ADAPTER"), 0, 0);
            StyleCombo(pingAdapterBox);
            pingAdapterBox.Dock = DockStyle.Fill;
            pingAdapterBox.SelectedIndexChanged += delegate { if (!loading) PopulateGatewayTargetModes(pingAdapterBox, pingTargetModeBox, pingTargetBox, true); };
            adapterRow.Controls.Add(pingAdapterBox, 1, 0);
            layout.Controls.Add(adapterRow, 0, 1);

            var modeRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 6, 0, 6) };
            modeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            modeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            modeRow.Controls.Add(FieldLabel("TARGET MODE"), 0, 0);
            StyleCombo(pingTargetModeBox);
            pingTargetModeBox.Dock = DockStyle.Fill;
            pingTargetModeBox.SelectedIndexChanged += delegate { if (!loading) ApplyGatewayTargetMode(pingTargetModeBox, pingTargetBox); };
            modeRow.Controls.Add(pingTargetModeBox, 1, 0);
            layout.Controls.Add(modeRow, 0, 2);

            var targetRow = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 6, 0, 6) };
            targetRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            targetRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            targetRow.Controls.Add(FieldLabel("TARGET"), 0, 0);
            pingTargetBox.Dock = DockStyle.Fill;
            pingTargetBox.BorderStyle = BorderStyle.FixedSingle;
            pingTargetBox.BackColor = Color.FromArgb(42, 50, 62);
            pingTargetBox.ForeColor = Color.White;
            pingTargetBox.TextChanged += delegate { if (!loading) SelectManualModeIfChanged(pingTargetModeBox, pingTargetBox); };
            targetRow.Controls.Add(pingTargetBox, 1, 0);
            layout.Controls.Add(targetRow, 0, 3);

            continuousPingCheck.Text = "Continuous ping (runs until stopped)";
            continuousPingCheck.Dock = DockStyle.Fill;
            continuousPingCheck.ForeColor = Color.White;
            continuousPingCheck.Padding = new Padding(92, 0, 0, 0);
            layout.Controls.Add(continuousPingCheck, 0, 4);

            var buttons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, BackColor = Back, Padding = new Padding(0, 7, 0, 7) };
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            pingStartButton = MakeButton("Start ping", delegate { StartPing(); }, true, 0);
            pingStopButton = MakeButton("Stop", delegate { StopPing(); }, false, 0);
            pingStopButton.Enabled = false;
            buttons.Controls.Add(pingStartButton, 0, 0);
            buttons.Controls.Add(pingStopButton, 1, 0);
            buttons.Controls.Add(MakeButton("Use gateway", delegate { UseGatewayForPing(); }, false, 0), 2, 0);
            layout.Controls.Add(buttons, 0, 5);

            var outputPanel = Card();
            pingOutputBox.Dock = DockStyle.Fill;
            pingOutputBox.ReadOnly = true;
            pingOutputBox.BackColor = Color.FromArgb(15, 20, 26);
            pingOutputBox.ForeColor = Color.FromArgb(214, 225, 235);
            pingOutputBox.BorderStyle = BorderStyle.None;
            pingOutputBox.Font = summaryRegularFont;
            pingOutputBox.WordWrap = false;
            pingOutputBox.ScrollBars = RichTextBoxScrollBars.Both;
            pingOutputBox.DetectUrls = false;
            pingOutputBox.Text = "Enter a hostname or IP address. Enable Continuous ping to run until you press Stop.";
            outputPanel.Controls.Add(pingOutputBox);
            layout.Controls.Add(outputPanel, 0, 6);
        }

        private void BuildConnectionTab(TabPage connectionTab)
        {
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(14), ColumnCount = 1, RowCount = 9, BackColor = Back };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            for (int i = 1; i <= 6; i++) layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 55));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            connectionTab.Controls.Add(layout);

            var heading = new Panel { Dock = DockStyle.Fill };
            heading.Controls.Add(new Label { Text = "TELNET / SSH", Font = new Font("Segoe UI Semibold", 14F), AutoSize = true, Location = new Point(0, 2), ForeColor = Color.White });
            connectionStatusLabel.Text = "Ready • Windows clients detected";
            connectionStatusLabel.AutoSize = true;
            connectionStatusLabel.Location = new Point(2, 31);
            connectionStatusLabel.ForeColor = Muted;
            heading.Controls.Add(connectionStatusLabel);
            layout.Controls.Add(heading, 0, 0);

            var adapterRow = ConnectionRow("ADAPTER");
            StyleCombo(connectionAdapterBox);
            connectionAdapterBox.Dock = DockStyle.Fill;
            connectionAdapterBox.SelectedIndexChanged += delegate { if (!loading) PopulateGatewayTargetModes(connectionAdapterBox, connectionTargetModeBox, connectionHostBox, true); };
            adapterRow.Controls.Add(connectionAdapterBox, 1, 0);
            layout.Controls.Add(adapterRow, 0, 1);

            var modeRow = ConnectionRow("TARGET MODE");
            StyleCombo(connectionTargetModeBox);
            connectionTargetModeBox.Dock = DockStyle.Fill;
            connectionTargetModeBox.SelectedIndexChanged += delegate { if (!loading) ApplyGatewayTargetMode(connectionTargetModeBox, connectionHostBox); };
            modeRow.Controls.Add(connectionTargetModeBox, 1, 0);
            layout.Controls.Add(modeRow, 0, 2);

            var protocolRow = ConnectionRow("PROTOCOL");
            StyleCombo(connectionProtocolBox);
            connectionProtocolBox.Dock = DockStyle.Fill;
            connectionProtocolBox.Items.AddRange(new object[] { "SSH", "Telnet" });
            connectionProtocolBox.SelectedIndexChanged += delegate
            {
                bool ssh = connectionProtocolBox.SelectedIndex == 0;
                connectionPortBox.Value = ssh ? 22 : 23;
                connectionUsernameBox.Enabled = ssh;
                connectionUsernameBox.BackColor = ssh ? Color.FromArgb(42, 50, 62) : Color.FromArgb(31, 37, 46);
            };
            protocolRow.Controls.Add(connectionProtocolBox, 1, 0);
            layout.Controls.Add(protocolRow, 0, 3);

            var hostRow = ConnectionRow("HOST");
            StyleConnectionTextBox(connectionHostBox);
            connectionHostBox.TextChanged += delegate { if (!loading) SelectManualModeIfChanged(connectionTargetModeBox, connectionHostBox); };
            hostRow.Controls.Add(connectionHostBox, 1, 0);
            layout.Controls.Add(hostRow, 0, 4);

            var portRow = ConnectionRow("PORT");
            connectionPortBox.Dock = DockStyle.Fill;
            connectionPortBox.Minimum = 1;
            connectionPortBox.Maximum = 65535;
            connectionPortBox.Value = 22;
            connectionPortBox.BackColor = Color.FromArgb(42, 50, 62);
            connectionPortBox.ForeColor = Color.White;
            connectionPortBox.BorderStyle = BorderStyle.FixedSingle;
            portRow.Controls.Add(connectionPortBox, 1, 0);
            layout.Controls.Add(portRow, 0, 5);

            var usernameRow = ConnectionRow("USERNAME");
            StyleConnectionTextBox(connectionUsernameBox);
            usernameRow.Controls.Add(connectionUsernameBox, 1, 0);
            layout.Controls.Add(usernameRow, 0, 6);

            var buttons = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 7, 0, 7) };
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
            buttons.Controls.Add(MakeButton("Open connection", delegate { OpenConnection(); }, true, 0), 0, 0);
            buttons.Controls.Add(MakeButton("Use gateway", delegate { UseGatewayForConnection(); }, false, 0), 1, 0);
            layout.Controls.Add(buttons, 0, 7);

            var notePanel = Card();
            var note = new Label
            {
                Dock = DockStyle.Fill,
                ForeColor = Color.FromArgb(214, 225, 235),
                Font = new Font("Segoe UI", 10F),
                TextAlign = ContentAlignment.TopLeft,
                Text = "The selected client opens in a separate interactive terminal.\r\n\r\nSSH uses the Windows OpenSSH client. Telnet uses the Windows Telnet client. Passwords and authentication prompts are handled only by that terminal and are never stored by Network Corner."
            };
            notePanel.Controls.Add(note);
            layout.Controls.Add(notePanel, 0, 8);
            connectionProtocolBox.SelectedIndex = 0;
        }

        private void BuildDiagnosticsTab(TabPage diagnosticsTab)
        {
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(14), ColumnCount = 1, RowCount = 5, BackColor = Back };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 180));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            diagnosticsTab.Controls.Add(layout);

            var heading = new Panel { Dock = DockStyle.Fill };
            heading.Controls.Add(new Label { Text = "NETWORK DIAGNOSTICS", Font = new Font("Segoe UI Semibold", 14F), AutoSize = true, Location = new Point(0, 2), ForeColor = Color.White });
            diagnosticsStatusLabel.Text = "Ready";
            diagnosticsStatusLabel.AutoSize = true;
            diagnosticsStatusLabel.Location = new Point(2, 31);
            diagnosticsStatusLabel.ForeColor = Muted;
            heading.Controls.Add(diagnosticsStatusLabel);
            layout.Controls.Add(heading, 0, 0);

            var targetRow = ConnectionRow("TARGET");
            StyleConnectionTextBox(diagnosticsTargetBox);
            targetRow.Controls.Add(diagnosticsTargetBox, 1, 0);
            layout.Controls.Add(targetRow, 0, 1);

            var portRow = ConnectionRow("TCP PORT");
            diagnosticsPortBox.Dock = DockStyle.Fill;
            diagnosticsPortBox.Minimum = 1;
            diagnosticsPortBox.Maximum = 65535;
            diagnosticsPortBox.Value = 80;
            diagnosticsPortBox.BackColor = Color.FromArgb(42, 50, 62);
            diagnosticsPortBox.ForeColor = Color.White;
            diagnosticsPortBox.BorderStyle = BorderStyle.FixedSingle;
            portRow.Controls.Add(diagnosticsPortBox, 1, 0);
            layout.Controls.Add(portRow, 0, 2);

            var actions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 4, BackColor = Back, Padding = new Padding(0, 5, 0, 5) };
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            for (int i = 0; i < 4; i++) actions.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            actions.Controls.Add(MakeButton("DNS lookup", delegate { RunDnsLookup(); }, false, 0), 0, 0);
            actions.Controls.Add(MakeButton("Traceroute", delegate { RunTraceroute(); }, false, 0), 1, 0);
            actions.Controls.Add(MakeButton("TCP port test", delegate { RunTcpPortTest(); }, false, 0), 0, 1);
            actions.Controls.Add(MakeButton("Public IP", delegate { RunPublicIpLookup(); }, false, 0), 1, 1);
            actions.Controls.Add(MakeButton("ARP table", delegate { StartDiagnosticProcess("ARP table", "arp.exe", "-a"); }, false, 0), 0, 2);
            actions.Controls.Add(MakeButton("Routing table", delegate { StartDiagnosticProcess("Routing table", "route.exe", "print"); }, false, 0), 1, 2);
            actions.Controls.Add(MakeButton("Flush DNS", delegate { FlushDns(); }, false, 0), 0, 3);
            diagnosticsStopButton = MakeButton("Stop", delegate { StopDiagnostic(); }, false, 0);
            diagnosticsStopButton.Enabled = false;
            actions.Controls.Add(diagnosticsStopButton, 1, 3);
            layout.Controls.Add(actions, 0, 3);

            var outputPanel = Card();
            diagnosticsOutputBox.Dock = DockStyle.Fill;
            diagnosticsOutputBox.ReadOnly = true;
            diagnosticsOutputBox.BackColor = Color.FromArgb(15, 20, 26);
            diagnosticsOutputBox.ForeColor = Color.FromArgb(214, 225, 235);
            diagnosticsOutputBox.BorderStyle = BorderStyle.None;
            diagnosticsOutputBox.Font = summaryRegularFont;
            diagnosticsOutputBox.WordWrap = false;
            diagnosticsOutputBox.ScrollBars = RichTextBoxScrollBars.Both;
            diagnosticsOutputBox.DetectUrls = false;
            diagnosticsOutputBox.Text = "Choose a diagnostic. Target-based tools use the hostname or IP address above.";
            outputPanel.Controls.Add(diagnosticsOutputBox);
            layout.Controls.Add(outputPanel, 0, 4);
        }

        private void RunDnsLookup()
        {
            string target = diagnosticsTargetBox.Text.Trim();
            string validation = ConnectionSupport.ValidateHost(target);
            if (validation != null) { MessageBox.Show(this, validation, "Check diagnostic target", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            StartBackgroundDiagnostic("DNS lookup", delegate
            {
                IPAddress[] addresses = Dns.GetHostAddresses(target);
                return "DNS results for " + target + ":\r\n\r\n" + String.Join("\r\n", addresses.Select(x => x.ToString()).ToArray());
            });
        }

        private void RunTraceroute()
        {
            string target = diagnosticsTargetBox.Text.Trim();
            string validation = ConnectionSupport.ValidateHost(target);
            if (validation != null) { MessageBox.Show(this, validation, "Check diagnostic target", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            StartDiagnosticProcess("Traceroute", "tracert.exe", "-d " + target);
        }

        private void RunTcpPortTest()
        {
            string target = diagnosticsTargetBox.Text.Trim();
            string validation = ConnectionSupport.ValidateHost(target);
            if (validation != null) { MessageBox.Show(this, validation, "Check diagnostic target", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            int port = Decimal.ToInt32(diagnosticsPortBox.Value);
            StartBackgroundDiagnostic("TCP port test", delegate
            {
                using (var client = new TcpClient())
                {
                    IAsyncResult result = client.BeginConnect(target, port, null, null);
                    bool connected = result.AsyncWaitHandle.WaitOne(2500);
                    if (!connected) return "TCP " + target + ":" + port + " did not respond within 2.5 seconds.";
                    client.EndConnect(result);
                    return "TCP " + target + ":" + port + " is open and accepted a connection.";
                }
            });
        }

        private void RunPublicIpLookup()
        {
            StartBackgroundDiagnostic("Public IP lookup", delegate
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
                using (var client = new WebClient())
                {
                    client.Headers[HttpRequestHeader.UserAgent] = "NetworkCorner/1.0";
                    string address = client.DownloadString("https://api.ipify.org").Trim();
                    return "Public IP address:\r\n\r\n" + address;
                }
            });
        }

        private void StartBackgroundDiagnostic(string label, Func<string> work)
        {
            if (diagnosticBusy) { MessageBox.Show(this, "Another diagnostic is already running.", "Diagnostic busy", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            diagnosticBusy = true;
            diagnosticsStopButton.Enabled = false;
            diagnosticsStatusLabel.Text = label + " running…";
            diagnosticsStatusLabel.ForeColor = Color.FromArgb(74, 193, 255);
            diagnosticsOutputBox.Clear();
            ThreadPool.QueueUserWorkItem(delegate
            {
                string result;
                bool success = true;
                try { result = work(); }
                catch (Exception ex) { result = ex.Message; success = false; }
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        AppendDiagnosticOutput(result + "\r\n", success ? Color.FromArgb(214, 225, 235) : Color.FromArgb(255, 130, 130));
                        diagnosticsStatusLabel.Text = success ? label + " complete" : label + " failed";
                        diagnosticsStatusLabel.ForeColor = success ? Color.FromArgb(92, 214, 147) : Color.FromArgb(255, 130, 130);
                        diagnosticBusy = false;
                    });
                }
                catch { diagnosticBusy = false; }
            });
        }

        private void StartDiagnosticProcess(string label, string executable, string arguments)
        {
            if (diagnosticBusy) { MessageBox.Show(this, "Another diagnostic is already running.", "Diagnostic busy", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            var process = new Process();
            process.StartInfo = new ProcessStartInfo(executable, arguments);
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.EnableRaisingEvents = true;
            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) AppendDiagnosticOutputSafe(e.Data + "\r\n", Color.FromArgb(214, 225, 235)); };
            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) AppendDiagnosticOutputSafe(e.Data + "\r\n", Color.FromArgb(255, 130, 130)); };
            process.Exited += delegate
            {
                int exitCode = process.ExitCode;
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        diagnosticsStatusLabel.Text = exitCode == 0 ? label + " complete" : label + " failed • exit code " + exitCode;
                        diagnosticsStatusLabel.ForeColor = exitCode == 0 ? Color.FromArgb(92, 214, 147) : Color.FromArgb(255, 130, 130);
                        diagnosticsStopButton.Enabled = false;
                        currentDiagnostic = null;
                        diagnosticBusy = false;
                        process.Dispose();
                    });
                }
                catch { process.Dispose(); }
            };
            try
            {
                diagnosticsOutputBox.Clear();
                diagnosticsStatusLabel.Text = label + " running…";
                diagnosticsStatusLabel.ForeColor = Color.FromArgb(74, 193, 255);
                diagnosticBusy = true;
                currentDiagnostic = process;
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                diagnosticsStopButton.Enabled = true;
            }
            catch (Exception ex)
            {
                diagnosticBusy = false;
                currentDiagnostic = null;
                process.Dispose();
                MessageBox.Show(this, ex.Message, "Could not start diagnostic", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StopDiagnostic()
        {
            try { if (currentDiagnostic != null && !currentDiagnostic.HasExited) currentDiagnostic.Kill(); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Could not stop diagnostic", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void FlushDns()
        {
            ExecuteElevatedRequest(new ChangeRequest { Operation = "flushdns" }, "This will clear the Windows DNS resolver cache. Continue?");
        }

        private void AppendDiagnosticOutputSafe(string text, Color color)
        {
            try { BeginInvoke((MethodInvoker)delegate { AppendDiagnosticOutput(text, color); }); } catch { }
        }

        private void AppendDiagnosticOutput(string text, Color color)
        {
            diagnosticsOutputBox.SelectionStart = diagnosticsOutputBox.TextLength;
            diagnosticsOutputBox.SelectionLength = 0;
            diagnosticsOutputBox.SelectionColor = color;
            diagnosticsOutputBox.AppendText(text);
            diagnosticsOutputBox.SelectionStart = diagnosticsOutputBox.TextLength;
            diagnosticsOutputBox.ScrollToCaret();
        }

        private TableLayoutPanel ConnectionRow(string label)
        {
            var row = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Back, Padding = new Padding(0, 6, 0, 6) };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.Controls.Add(FieldLabel(label), 0, 0);
            return row;
        }

        private void StyleConnectionTextBox(TextBox box)
        {
            box.Dock = DockStyle.Fill;
            box.BorderStyle = BorderStyle.FixedSingle;
            box.BackColor = Color.FromArgb(42, 50, 62);
            box.ForeColor = Color.White;
        }

        private void OpenConnection()
        {
            string host = connectionHostBox.Text.Trim();
            string validation = ConnectionSupport.ValidateHost(host);
            if (validation == null && connectionProtocolBox.SelectedIndex == 0)
                validation = ConnectionSupport.ValidateUsername(connectionUsernameBox.Text);
            if (validation != null)
            {
                MessageBox.Show(this, validation, "Check connection settings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            AdapterInfo selectedAdapter = connectionAdapterBox.SelectedItem as AdapterInfo;
            if (selectedAdapter == null)
            {
                MessageBox.Show(this, "Choose an adapter for the connection.", "Adapter required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            bool ssh = connectionProtocolBox.SelectedIndex == 0;
            int port = Decimal.ToInt32(connectionPortBox.Value);
            string systemFolder = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string executable = ssh ? Path.Combine(systemFolder, "OpenSSH", "ssh.exe") : Path.Combine(systemFolder, "telnet.exe");
            if (!File.Exists(executable))
            {
                MessageBox.Show(this, (ssh ? "OpenSSH" : "Telnet") + " is not installed on this computer.", "Client unavailable", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                var start = new ProcessStartInfo(executable, ConnectionSupport.BuildClientArguments(ssh, host, port, connectionUsernameBox.Text, ssh ? selectedAdapter.Address : null));
                start.UseShellExecute = true;
                Process.Start(start);
                connectionStatusLabel.Text = (ssh ? "SSH" : "Telnet") + " client opened for " + host + ":" + port;
                connectionStatusLabel.ForeColor = Color.FromArgb(92, 214, 147);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Could not open connection", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void UseGatewayForConnection()
        {
            AdapterInfo selected = connectionAdapterBox.SelectedItem as AdapterInfo;
            if (selected == null || String.IsNullOrWhiteSpace(selected.Gateway))
            {
                MessageBox.Show(this, "The selected adapter does not currently report an IPv4 gateway.", "Gateway unavailable", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            connectionHostBox.Text = selected.Gateway;
        }

        private void StartPing()
        {
            if (currentPing != null && !currentPing.HasExited) return;
            string target = pingTargetBox.Text.Trim();
            string validation = PingSupport.ValidateTarget(target);
            if (validation != null)
            {
                MessageBox.Show(this, validation, "Check ping target", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            AdapterInfo selectedAdapter = pingAdapterBox.SelectedItem as AdapterInfo;
            if (selectedAdapter == null || String.IsNullOrWhiteSpace(selectedAdapter.Address))
            {
                MessageBox.Show(this, "Choose an adapter with an IPv4 address.", "Adapter required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            bool continuous = continuousPingCheck.Checked;
            pingOutputBox.Clear();
            AppendPingOutput("Pinging " + target + (continuous ? " continuously" : " four times") + "…\r\nAdapter: " + selectedAdapter + " (source " + selectedAdapter.Address + ")\r\n\r\n", Accent);
            var process = new Process();
            process.StartInfo = new ProcessStartInfo("ping.exe", PingSupport.ArgumentsFor(target, continuous, selectedAdapter.Address));
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.EnableRaisingEvents = true;
            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) AppendPingOutputSafe(e.Data + "\r\n", Color.FromArgb(214, 225, 235)); };
            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) AppendPingOutputSafe(e.Data + "\r\n", Color.FromArgb(255, 130, 130)); };
            process.Exited += delegate(object sender, EventArgs e)
            {
                int exitCode = process.ExitCode;
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        pingStatusLabel.Text = exitCode == 0 ? "Ping complete" : "Ping stopped • exit code " + exitCode;
                        pingStatusLabel.ForeColor = exitCode == 0 ? Color.FromArgb(92, 214, 147) : Color.FromArgb(255, 190, 83);
                        pingStartButton.Enabled = true;
                        pingStopButton.Enabled = false;
                        pingTargetBox.Enabled = true;
                        continuousPingCheck.Enabled = true;
                        AppendPingOutput("\r\n" + pingStatusLabel.Text + ".\r\n", pingStatusLabel.ForeColor);
                        currentPing = null;
                        process.Dispose();
                    });
                }
                catch { process.Dispose(); }
            };

            try
            {
                currentPing = process;
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                pingStatusLabel.Text = continuous ? "Continuous ping running…" : "Pinging " + target + "…";
                pingStatusLabel.ForeColor = Color.FromArgb(74, 193, 255);
                pingStartButton.Enabled = false;
                pingStopButton.Enabled = true;
                pingTargetBox.Enabled = false;
                continuousPingCheck.Enabled = false;
            }
            catch (Exception ex)
            {
                currentPing = null;
                process.Dispose();
                pingStartButton.Enabled = true;
                pingStopButton.Enabled = false;
                MessageBox.Show(this, ex.Message, "Could not start ping", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StopPing()
        {
            try
            {
                if (currentPing != null && !currentPing.HasExited)
                {
                    pingStatusLabel.Text = "Stopping ping…";
                    currentPing.Kill();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Could not stop ping", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void UseGatewayForPing()
        {
            AdapterInfo selected = pingAdapterBox.SelectedItem as AdapterInfo;
            if (selected == null || String.IsNullOrWhiteSpace(selected.Gateway))
            {
                MessageBox.Show(this, "The selected adapter does not currently report an IPv4 gateway.", "Gateway unavailable", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            pingTargetBox.Text = selected.Gateway;
        }

        private void AppendPingOutputSafe(string text, Color color)
        {
            try { BeginInvoke((MethodInvoker)delegate { AppendPingOutput(text, color); }); }
            catch { }
        }

        private void AppendPingOutput(string text, Color color)
        {
            pingOutputBox.SelectionStart = pingOutputBox.TextLength;
            pingOutputBox.SelectionLength = 0;
            pingOutputBox.SelectionColor = color;
            pingOutputBox.AppendText(text);
            pingOutputBox.SelectionStart = pingOutputBox.TextLength;
            pingOutputBox.ScrollToCaret();
        }

        private void StartScan()
        {
            if (currentScan != null && !currentScan.HasExited) return;
            string target = scanTargetBox.Text.Trim();
            string validation = NmapSupport.ValidateTarget(target);
            if (validation != null)
            {
                MessageBox.Show(this, validation, "Check scan target", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string executable = NmapSupport.FindExecutable();
            if (String.IsNullOrWhiteSpace(executable))
            {
                MessageBox.Show(this, "Nmap was not found. Install Nmap for Windows and reopen Network Corner.", "Nmap unavailable", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            AdapterInfo selectedAdapter = scanAdapterBox.SelectedItem as AdapterInfo;
            if (selectedAdapter == null)
            {
                MessageBox.Show(this, "Choose an adapter for the scan.", "Adapter required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string interfaceName;
            if (!nmapInterfaces.TryGetValue((selectedAdapter.Id ?? "").Trim('{', '}'), out interfaceName))
            {
                nmapInterfaces = NmapSupport.GetInterfaceMap(executable);
                if (!nmapInterfaces.TryGetValue((selectedAdapter.Id ?? "").Trim('{', '}'), out interfaceName))
                {
                    MessageBox.Show(this, "Nmap could not map the selected Windows adapter to a capture interface. Refresh the adapter list and try again.", "Nmap interface unavailable", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }

            scanOutputBox.Clear();
            AppendScanOutput("Scanning " + target + " using “" + scanPresetBox.SelectedItem + "”\r\nAdapter: " + selectedAdapter + " (" + interfaceName + ")\r\n\r\n", Accent);
            var process = new Process();
            process.StartInfo = new ProcessStartInfo(executable, NmapSupport.ArgumentsFor(scanPresetBox.SelectedIndex, target, interfaceName));
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.EnableRaisingEvents = true;
            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) AppendScanOutputSafe(e.Data + "\r\n", Color.FromArgb(214, 225, 235)); };
            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) AppendScanOutputSafe(e.Data + "\r\n", Color.FromArgb(255, 130, 130)); };
            process.Exited += delegate(object sender, EventArgs e)
            {
                int exitCode = process.ExitCode;
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        scanStatusLabel.Text = exitCode == 0 ? "Scan complete" : "Scan stopped • exit code " + exitCode;
                        scanStatusLabel.ForeColor = exitCode == 0 ? Color.FromArgb(92, 214, 147) : Color.FromArgb(255, 190, 83);
                        scanStartButton.Enabled = true;
                        scanCancelButton.Enabled = false;
                        AppendScanOutput("\r\n" + scanStatusLabel.Text + ".\r\n", scanStatusLabel.ForeColor);
                        currentScan = null;
                        process.Dispose();
                    });
                }
                catch { process.Dispose(); }
            };

            try
            {
                currentScan = process;
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                scanStatusLabel.Text = "Scanning " + target + "…";
                scanStatusLabel.ForeColor = Color.FromArgb(74, 193, 255);
                scanStartButton.Enabled = false;
                scanCancelButton.Enabled = true;
            }
            catch (Exception ex)
            {
                currentScan = null;
                process.Dispose();
                scanStartButton.Enabled = true;
                scanCancelButton.Enabled = false;
                MessageBox.Show(this, ex.Message, "Could not start Nmap", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void CancelScan()
        {
            try
            {
                if (currentScan != null && !currentScan.HasExited)
                {
                    scanStatusLabel.Text = "Cancelling scan…";
                    currentScan.Kill();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Could not cancel scan", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void UseGatewayTarget()
        {
            AdapterInfo selected = scanAdapterBox.SelectedItem as AdapterInfo;
            if (selected == null || String.IsNullOrWhiteSpace(selected.Gateway))
            {
                MessageBox.Show(this, "The selected adapter does not currently report an IPv4 gateway.", "Gateway unavailable", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            scanTargetBox.Text = selected.Gateway;
        }

        private void AppendScanOutputSafe(string text, Color color)
        {
            try { BeginInvoke((MethodInvoker)delegate { AppendScanOutput(text, color); }); }
            catch { }
        }

        private void AppendScanOutput(string text, Color color)
        {
            scanOutputBox.SelectionStart = scanOutputBox.TextLength;
            scanOutputBox.SelectionLength = 0;
            scanOutputBox.SelectionColor = color;
            scanOutputBox.AppendText(text);
            scanOutputBox.SelectionStart = scanOutputBox.TextLength;
            scanOutputBox.ScrollToCaret();
        }

        private Panel Card()
        {
            return new Panel { Dock = DockStyle.Fill, Padding = new Padding(12), BackColor = Panel };
        }

        private Label FieldLabel(string text)
        {
            return new Label { Text = text, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Muted, Font = new Font("Segoe UI Semibold", 8F) };
        }

        private void AddField(TableLayoutPanel panel, int row, string label, TextBox box)
        {
            panel.Controls.Add(FieldLabel(label.ToUpperInvariant()), 0, row);
            box.Dock = DockStyle.Fill;
            box.BorderStyle = BorderStyle.FixedSingle;
            box.BackColor = Color.FromArgb(42, 50, 62);
            box.ForeColor = Color.White;
            box.Margin = new Padding(0, 4, 0, 4);
            panel.Controls.Add(box, 1, row);
        }

        private void StyleCombo(ComboBox box)
        {
            box.DropDownStyle = ComboBoxStyle.DropDownList;
            box.FlatStyle = FlatStyle.Flat;
            box.BackColor = Color.FromArgb(42, 50, 62);
            box.ForeColor = Color.White;
        }

        private Button MakeButton(string text, EventHandler click, bool primary, int width)
        {
            var button = new Button { Text = text, Dock = width == 0 ? DockStyle.Fill : DockStyle.None, Width = width, Height = 36, FlatStyle = FlatStyle.Flat, Margin = new Padding(3) };
            button.FlatAppearance.BorderSize = primary ? 0 : 1;
            button.FlatAppearance.BorderColor = Color.FromArgb(75, 87, 102);
            button.BackColor = primary ? Accent : Color.FromArgb(37, 45, 56);
            button.ForeColor = primary ? Color.FromArgb(10, 30, 28) : Color.White;
            button.Font = new Font("Segoe UI Semibold", 9F);
            button.Click += click;
            return button;
        }

        private void RefreshAdapters(bool populate)
        {
            string selected = adapterBox.SelectedItem is AdapterInfo ? ((AdapterInfo)adapterBox.SelectedItem).Name : null;
            List<AdapterInfo> detectedAdapters = NetworkReader.GetAdapters();
            adapters = hideDownCheck.Checked ? detectedAdapters.Where(x => x.Status == "Connected").ToList() : detectedAdapters;
            summaryBox.SuspendLayout();
            summaryBox.Clear();
            foreach (AdapterInfo a in adapters)
            {
                Color adapterColor = a.Kind == "Wi-Fi" ? Color.FromArgb(74, 193, 255) : Color.FromArgb(255, 157, 92);
                Color statusColor = a.Status == "Connected" ? Color.FromArgb(92, 214, 147) : Muted;
                Color assignmentColor = a.Assignment == "Static" ? Color.FromArgb(255, 190, 83) :
                                        a.Assignment.StartsWith("Dynamic") ? Color.FromArgb(92, 214, 147) : Muted;
                AppendSummary(a.Kind.ToUpperInvariant(), adapterColor, true);
                AppendSummary("  " + a.Name + "  [", Color.FromArgb(220, 228, 238), false);
                AppendSummary(a.Status, statusColor, true);
                AppendSummary(" • ", Muted, false);
                AppendSummary(a.Assignment, assignmentColor, true);
                AppendSummary("]\r\n", Color.FromArgb(220, 228, 238), false);
                AppendDetail("IP", Empty(a.Address));
                AppendDetail("MASK", Empty(a.Mask));
                AppendDetail("GW", Empty(a.Gateway));
                AppendDetail("DNS", Empty(a.Dns1) + (String.IsNullOrWhiteSpace(a.Dns2) ? "" : ", " + a.Dns2));
                AppendSummary("\r\n", Muted, false);
            }
            if (adapters.Count == 0) AppendSummary("No Wi-Fi or Ethernet adapters found.", Muted, false);
            summaryBox.SelectionStart = 0;
            summaryBox.ScrollToCaret();
            summaryBox.ResumeLayout();
            updatedLabel.Text = "Updated " + DateTime.Now.ToString("HH:mm:ss") + "  •  always on top";

            loading = true;
            adapterBox.Items.Clear();
            foreach (AdapterInfo a in adapters) adapterBox.Items.Add(a);
            int index = adapters.FindIndex(x => x.Name == selected);
            if (index < 0 && adapters.Count > 0) index = 0;
            if (index >= 0) adapterBox.SelectedIndex = index;
            RefreshScanNetworks();
            RefreshToolAdapterChoices();
            loading = false;
            if (populate) PopulateFields();
            UpdateDhcpButtons();
        }

        private void RefreshScanNetworks()
        {
            string selectedAdapterId = null;
            AdapterInfo previousAdapter = scanAdapterBox.SelectedItem as AdapterInfo;
            if (previousAdapter != null) selectedAdapterId = previousAdapter.Id;
            string selectedTarget = null;
            ScanNetworkOption selected = scanNetworkBox.SelectedItem as ScanNetworkOption;
            if (selected != null) selectedTarget = selected.Target;
            bool preserveManual = selected != null && selected.IsManual;

            if (nmapInterfaces.Count == 0) nmapInterfaces = NmapSupport.GetInterfaceMap(NmapSupport.FindExecutable());
            scanAdapterBox.Items.Clear();
            foreach (AdapterInfo adapter in adapters) scanAdapterBox.Items.Add(adapter);
            int adapterIndex = adapters.FindIndex(x => String.Equals(x.Id, selectedAdapterId, StringComparison.OrdinalIgnoreCase));
            if (adapterIndex < 0 && adapters.Count > 0) adapterIndex = 0;
            if (adapterIndex >= 0) scanAdapterBox.SelectedIndex = adapterIndex;
            PopulateScanNetworks(selectedTarget, preserveManual, false);
        }

        private void RefreshToolAdapterChoices()
        {
            RefreshAdapterCombo(pingAdapterBox);
            RefreshAdapterCombo(connectionAdapterBox);
            PopulateGatewayTargetModes(pingAdapterBox, pingTargetModeBox, pingTargetBox, false);
            PopulateGatewayTargetModes(connectionAdapterBox, connectionTargetModeBox, connectionHostBox, false);
        }

        private void RefreshAdapterCombo(ComboBox box)
        {
            AdapterInfo previous = box.SelectedItem as AdapterInfo;
            string selectedId = previous == null ? null : previous.Id;
            box.Items.Clear();
            foreach (AdapterInfo adapter in adapters) box.Items.Add(adapter);
            int index = adapters.FindIndex(x => String.Equals(x.Id, selectedId, StringComparison.OrdinalIgnoreCase));
            if (index < 0 && adapters.Count > 0) index = 0;
            if (index >= 0) box.SelectedIndex = index;
        }

        private void PopulateGatewayTargetModes(ComboBox adapterChoice, ComboBox modeChoice, TextBox targetBox, bool updateTarget)
        {
            bool previousLoading = loading;
            loading = true;
            ScanNetworkOption previous = modeChoice.SelectedItem as ScanNetworkOption;
            bool preserveManual = previous != null && previous.IsManual;
            string selectedTarget = previous == null ? null : previous.Target;
            modeChoice.Items.Clear();
            AdapterInfo adapter = adapterChoice.SelectedItem as AdapterInfo;
            if (adapter != null && !String.IsNullOrWhiteSpace(adapter.Gateway))
                modeChoice.Items.Add(new ScanNetworkOption { Label = "Gateway IP — " + adapter.Gateway, Target = adapter.Gateway });
            modeChoice.Items.Add(new ScanNetworkOption { Label = "Manual target", IsManual = true });
            int manualIndex = modeChoice.Items.Count - 1;
            int selectedIndex = preserveManual ? manualIndex : 0;
            if (!String.IsNullOrWhiteSpace(selectedTarget))
            {
                for (int i = 0; i < modeChoice.Items.Count; i++)
                {
                    ScanNetworkOption option = modeChoice.Items[i] as ScanNetworkOption;
                    if (option != null && String.Equals(option.Target, selectedTarget, StringComparison.OrdinalIgnoreCase)) { selectedIndex = i; break; }
                }
            }
            modeChoice.SelectedIndex = selectedIndex;
            if (updateTarget || (previous == null && selectedIndex != manualIndex))
            {
                ScanNetworkOption option = modeChoice.SelectedItem as ScanNetworkOption;
                if (option != null && !String.IsNullOrWhiteSpace(option.Target)) targetBox.Text = option.Target;
            }
            loading = previousLoading;
        }

        private void ApplyGatewayTargetMode(ComboBox modeChoice, TextBox targetBox)
        {
            ScanNetworkOption option = modeChoice.SelectedItem as ScanNetworkOption;
            if (option == null || String.IsNullOrWhiteSpace(option.Target)) return;
            loading = true;
            targetBox.Text = option.Target;
            loading = false;
        }

        private void SelectManualModeIfChanged(ComboBox modeChoice, TextBox targetBox)
        {
            ScanNetworkOption selected = modeChoice.SelectedItem as ScanNetworkOption;
            if (selected == null || selected.IsManual || String.Equals(selected.Target, targetBox.Text.Trim(), StringComparison.OrdinalIgnoreCase)) return;
            for (int i = 0; i < modeChoice.Items.Count; i++)
            {
                ScanNetworkOption option = modeChoice.Items[i] as ScanNetworkOption;
                if (option != null && option.IsManual) { modeChoice.SelectedIndex = i; break; }
            }
        }

        private void PopulateScanNetworks(string selectedTarget, bool preserveManual, bool updateTarget)
        {
            bool previousLoading = loading;
            loading = true;
            scanNetworkBox.Items.Clear();
            AdapterInfo adapter = scanAdapterBox.SelectedItem as AdapterInfo;
            if (adapter != null)
            {
                if (!String.IsNullOrWhiteSpace(adapter.Gateway))
                {
                    scanNetworkBox.Items.Add(new ScanNetworkOption
                    {
                        Label = "Gateway IP — " + adapter.Gateway,
                        Target = adapter.Gateway
                    });
                }
                string target = NmapSupport.NetworkTarget(adapter.Address, adapter.Mask);
                if (!String.IsNullOrWhiteSpace(target))
                {
                    scanNetworkBox.Items.Add(new ScanNetworkOption
                    {
                        Label = "Full network scan — " + target,
                        Target = target
                    });
                }
            }
            scanNetworkBox.Items.Add(new ScanNetworkOption { Label = "Manual target", Target = null, IsManual = true });
            int manualIndex = scanNetworkBox.Items.Count - 1;
            int selectedIndex = preserveManual ? manualIndex : 0;
            if (!String.IsNullOrWhiteSpace(selectedTarget))
            {
                for (int i = 0; i < scanNetworkBox.Items.Count; i++)
                {
                    ScanNetworkOption option = scanNetworkBox.Items[i] as ScanNetworkOption;
                    if (option != null && String.Equals(option.Target, selectedTarget, StringComparison.OrdinalIgnoreCase)) { selectedIndex = i; break; }
                }
            }
            scanNetworkBox.SelectedIndex = selectedIndex;
            if (updateTarget || (String.IsNullOrWhiteSpace(selectedTarget) && !preserveManual))
            {
                ScanNetworkOption option = scanNetworkBox.SelectedItem as ScanNetworkOption;
                if (option != null && !String.IsNullOrWhiteSpace(option.Target)) scanTargetBox.Text = option.Target;
            }
            loading = previousLoading;
        }

        private static string Empty(string value) { return String.IsNullOrWhiteSpace(value) ? "—" : value; }

        private void AppendDetail(string label, string value)
        {
            AppendSummary("  " + label.PadRight(5), Muted, false);
            AppendSummary(value + "\r\n", Color.FromArgb(220, 228, 238), false);
        }

        private void AppendSummary(string text, Color color, bool bold)
        {
            summaryBox.SelectionStart = summaryBox.TextLength;
            summaryBox.SelectionLength = 0;
            summaryBox.SelectionColor = color;
            summaryBox.SelectionFont = bold ? summaryBoldFont : summaryRegularFont;
            summaryBox.AppendText(text);
        }

        private void PopulateFields()
        {
            AdapterInfo a = adapterBox.SelectedItem as AdapterInfo;
            if (a == null) { UpdateDhcpButtons(); return; }
            addressBox.Text = a.Address;
            maskBox.Text = a.Mask;
            gatewayBox.Text = a.Gateway;
            dns1Box.Text = a.Dns1;
            dns2Box.Text = a.Dns2;
            if (String.IsNullOrWhiteSpace(pingTargetBox.Text) && !String.IsNullOrWhiteSpace(a.Gateway)) pingTargetBox.Text = a.Gateway;
            if (String.IsNullOrWhiteSpace(connectionHostBox.Text) && !String.IsNullOrWhiteSpace(a.Gateway)) connectionHostBox.Text = a.Gateway;
            if (String.IsNullOrWhiteSpace(diagnosticsTargetBox.Text) && !String.IsNullOrWhiteSpace(a.Gateway)) diagnosticsTargetBox.Text = a.Gateway;
            profileBox.SelectedIndex = -1;
            UpdateDhcpButtons();
        }

        private void UpdateDhcpButtons()
        {
            AdapterInfo adapter = adapterBox.SelectedItem as AdapterInfo;
            bool isDhcp = adapter != null && !String.IsNullOrWhiteSpace(adapter.Assignment) && adapter.Assignment.StartsWith("Dynamic", StringComparison.OrdinalIgnoreCase);
            if (releaseIpButton != null) releaseIpButton.Enabled = isDhcp;
            if (renewIpButton != null) renewIpButton.Enabled = isDhcp;
        }

        private ChangeRequest CurrentRequest(bool dhcp)
        {
            AdapterInfo adapter = adapterBox.SelectedItem as AdapterInfo;
            return new ChangeRequest
            {
                Adapter = adapter == null ? "" : adapter.Name,
                Dhcp = dhcp,
                Address = addressBox.Text.Trim(),
                Mask = maskBox.Text.Trim(),
                Gateway = gatewayBox.Text.Trim(),
                Dns1 = dns1Box.Text.Trim(),
                Dns2 = dns2Box.Text.Trim()
            };
        }

        private void Apply(bool dhcp)
        {
            ChangeRequest request = CurrentRequest(dhcp);
            string validation = RequestValidator.Validate(request);
            if (validation != null)
            {
                MessageBox.Show(this, validation, "Check network settings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            AdapterInfo selectedAdapter = adapterBox.SelectedItem as AdapterInfo;
            if (!dhcp && StaticAddressAppearsInUse(request.Address, selectedAdapter))
            {
                string warning = "The proposed IP address " + request.Address + " responded on the network or is assigned to another local adapter. It may already be in use. Apply it anyway?";
                if (MessageBox.Show(this, warning, "Possible IP address conflict", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            }
            string action = dhcp ? "switch " + request.Adapter + " to DHCP" : "apply these static settings to " + request.Adapter;
            ExecuteElevatedRequest(request, "This will " + action + ". Connectivity may briefly drop. Continue?");
        }

        private bool StaticAddressAppearsInUse(string address, AdapterInfo selectedAdapter)
        {
            if (selectedAdapter != null && String.Equals(selectedAdapter.Address, address, StringComparison.OrdinalIgnoreCase)) return false;
            if (adapters.Any(x => x != selectedAdapter && String.Equals(x.Address, address, StringComparison.OrdinalIgnoreCase))) return true;
            try
            {
                using (var ping = new Ping())
                {
                    PingReply reply = ping.Send(address, 700);
                    return reply != null && reply.Status == IPStatus.Success;
                }
            }
            catch { return false; }
        }

        private void RunIpOperation(string operation)
        {
            AdapterInfo adapter = adapterBox.SelectedItem as AdapterInfo;
            var request = new ChangeRequest
            {
                Adapter = adapter == null ? "" : adapter.Name,
                Operation = operation
            };
            string validation = RequestValidator.Validate(request);
            if (validation != null)
            {
                MessageBox.Show(this, validation, "Check network adapter", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string verb = operation == "release" ? "release" : "renew";
            string warning = operation == "release" ? " This will temporarily remove its DHCP address." : "";
            ExecuteElevatedRequest(request, "This will " + verb + " the DHCP lease for " + request.Adapter + "." + warning + " Continue?");
        }

        private void ExecuteElevatedRequest(ChangeRequest request, string confirmation)
        {
            if (MessageBox.Show(this, confirmation, "Confirm network change", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            string tempPath = Path.Combine(Path.GetTempPath(), "NetworkCorner-" + Guid.NewGuid().ToString("N") + ".json");
            try
            {
                File.WriteAllText(tempPath, new JavaScriptSerializer().Serialize(request), Encoding.UTF8);
                var psi = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--apply-file \"" + tempPath + "\"");
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                using (Process helper = Process.Start(psi)) { helper.WaitForExit(); }
                RefreshAdapters(true);
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                if (ex.NativeErrorCode != 1223) MessageBox.Show(this, ex.Message, "Could not start network change", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Could not start network change", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }
        }

        private void LoadPreferences()
        {
            if (!File.Exists(preferencesPath)) return;
            try
            {
                AppPreferences preferences = new JavaScriptSerializer().Deserialize<AppPreferences>(File.ReadAllText(preferencesPath, Encoding.UTF8));
                if (preferences == null) return;
                loading = true;
                if (preferences.WindowWidth >= MinimumSize.Width && preferences.WindowHeight >= MinimumSize.Height)
                    Size = new Size(preferences.WindowWidth, preferences.WindowHeight);
                if (preferences.MonitorIndex >= 0 && preferences.MonitorIndex < screenBox.Items.Count) screenBox.SelectedIndex = preferences.MonitorIndex;
                if (preferences.CornerIndex >= 0 && preferences.CornerIndex < cornerBox.Items.Count) cornerBox.SelectedIndex = preferences.CornerIndex;
                fullHeightCheck.Checked = preferences.FullHeight;
                hideDownCheck.Checked = preferences.HideDownAdapters;
                if (preferences.SelectedTabIndex >= 0 && preferences.SelectedTabIndex < mainTabs.TabPages.Count) mainTabs.SelectedIndex = preferences.SelectedTabIndex;
                loading = false;
            }
            catch { loading = false; }
        }

        private void SavePreferences()
        {
            try
            {
                var preferences = new AppPreferences
                {
                    MonitorIndex = screenBox.SelectedIndex,
                    CornerIndex = cornerBox.SelectedIndex,
                    FullHeight = fullHeightCheck.Checked,
                    HideDownAdapters = hideDownCheck.Checked,
                    SelectedTabIndex = mainTabs.SelectedIndex,
                    WindowWidth = Width,
                    WindowHeight = fullHeightCheck.Checked && normalHeight > 0 ? normalHeight : Height
                };
                Directory.CreateDirectory(Path.GetDirectoryName(preferencesPath));
                File.WriteAllText(preferencesPath, new JavaScriptSerializer().Serialize(preferences), Encoding.UTF8);
            }
            catch { }
        }

        private void LoadProfiles()
        {
            try
            {
                if (File.Exists(profilePath)) profiles = new JavaScriptSerializer().Deserialize<List<NetworkProfile>>(File.ReadAllText(profilePath, Encoding.UTF8)) ?? new List<NetworkProfile>();
            }
            catch { profiles = new List<NetworkProfile>(); }
            if (!profiles.Any(x => String.Equals(x.Name, "TFTP", StringComparison.OrdinalIgnoreCase)))
            {
                profiles.Add(new NetworkProfile
                {
                    Name = "TFTP",
                    Address = "192.168.1.10",
                    Mask = "255.255.255.0",
                    Gateway = "192.168.1.1",
                    Dns1 = "8.8.8.8",
                    Dns2 = "8.8.4.4"
                });
                SaveProfiles();
            }
            ReloadProfileBox();
        }

        private void ReloadProfileBox()
        {
            loading = true;
            profileBox.Items.Clear();
            foreach (NetworkProfile p in profiles.OrderBy(x => x.Name)) profileBox.Items.Add(p.Name);
            profileBox.SelectedIndex = -1;
            loading = false;
        }

        private void SaveProfile()
        {
            string name = Prompt.Show(this, "Profile name", "Save network profile");
            if (String.IsNullOrWhiteSpace(name)) return;
            NetworkProfile p = profiles.FirstOrDefault(x => String.Equals(x.Name, name.Trim(), StringComparison.OrdinalIgnoreCase));
            if (p == null) { p = new NetworkProfile(); profiles.Add(p); }
            p.Name = name.Trim(); p.Address = addressBox.Text.Trim(); p.Mask = maskBox.Text.Trim(); p.Gateway = gatewayBox.Text.Trim(); p.Dns1 = dns1Box.Text.Trim(); p.Dns2 = dns2Box.Text.Trim();
            SaveProfiles();
            ReloadProfileBox();
            profileBox.SelectedItem = p.Name;
        }

        private void DeleteProfile()
        {
            if (profileBox.SelectedItem == null) return;
            string name = profileBox.SelectedItem.ToString();
            if (MessageBox.Show(this, "Delete profile ‘" + name + "’?", "Delete profile", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            profiles.RemoveAll(x => String.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));
            SaveProfiles();
            ReloadProfileBox();
        }

        private void SaveProfiles()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(profilePath));
            File.WriteAllText(profilePath, new JavaScriptSerializer().Serialize(profiles), Encoding.UTF8);
        }

        private void LoadSelectedProfile()
        {
            if (profileBox.SelectedItem == null) return;
            NetworkProfile p = profiles.FirstOrDefault(x => x.Name == profileBox.SelectedItem.ToString());
            if (p == null) return;
            addressBox.Text = p.Address; maskBox.Text = p.Mask; gatewayBox.Text = p.Gateway; dns1Box.Text = p.Dns1; dns2Box.Text = p.Dns2;
        }

        private void LoadScreens()
        {
            screenBox.Items.Clear();
            for (int i = 0; i < Screen.AllScreens.Length; i++) screenBox.Items.Add("Monitor " + (i + 1));
            int primary = Array.FindIndex(Screen.AllScreens, x => x.Primary);
            screenBox.SelectedIndex = primary < 0 ? 0 : primary;
        }

        private void DockToCorner()
        {
            if (!IsHandleCreated || screenBox.SelectedIndex < 0 || cornerBox.SelectedIndex < 0) return;
            Screen[] screens = Screen.AllScreens;
            if (screenBox.SelectedIndex >= screens.Length) return;
            Rectangle area = screens[screenBox.SelectedIndex].WorkingArea;
            const int gap = 10;
            if (fullHeightCheck.Checked)
                Height = Math.Max(MinimumSize.Height, area.Height - (gap * 2));
            else if (normalHeight > 0)
                Height = normalHeight;
            string corner = cornerBox.SelectedItem.ToString();
            int x = corner.Contains("right") ? area.Right - Width - gap : area.Left + gap;
            int y = fullHeightCheck.Checked ? area.Top + gap : (corner.StartsWith("Bottom") ? area.Bottom - Height - gap : area.Top + gap);
            Location = new Point(x, y);
        }
    }

    internal static class Prompt
    {
        public static string Show(IWin32Window owner, string label, string title)
        {
            using (var form = new Form())
            using (var input = new TextBox())
            using (var ok = new Button())
            using (var cancel = new Button())
            {
                form.Text = title; form.ClientSize = new Size(330, 112); form.FormBorderStyle = FormBorderStyle.FixedDialog; form.StartPosition = FormStartPosition.CenterParent; form.MinimizeBox = false; form.MaximizeBox = false; form.ShowInTaskbar = false;
                var prompt = new Label { Text = label, Left = 12, Top = 12, Width = 300 };
                input.Left = 12; input.Top = 35; input.Width = 306;
                ok.Text = "Save"; ok.Left = 162; ok.Top = 72; ok.Width = 75; ok.DialogResult = DialogResult.OK;
                cancel.Text = "Cancel"; cancel.Left = 243; cancel.Top = 72; cancel.Width = 75; cancel.DialogResult = DialogResult.Cancel;
                form.Controls.AddRange(new Control[] { prompt, input, ok, cancel }); form.AcceptButton = ok; form.CancelButton = cancel;
                return form.ShowDialog(owner) == DialogResult.OK ? input.Text : null;
            }
        }
    }

    internal static class SelfTests
    {
        public static int Run()
        {
            int failures = 0;
            failures += Check(RequestValidator.Validate(new ChangeRequest { Adapter = "Ethernet", Address = "192.168.1.20", Mask = "255.255.255.0", Gateway = "192.168.1.1", Dns1 = "1.1.1.1" }) == null, "valid static request");
            failures += Check(RequestValidator.Validate(new ChangeRequest { Adapter = "Ethernet", Address = "999.1.1.1", Mask = "255.255.255.0" }) != null, "invalid address");
            failures += Check(RequestValidator.Validate(new ChangeRequest { Adapter = "Ethernet", Address = "10.0.0.2", Mask = "255.0.255.0" }) != null, "non-contiguous mask");
            var dhcp = NetworkChanger.BuildCommands(new ChangeRequest { Adapter = "Wi-Fi", Dhcp = true });
            failures += Check(dhcp.Count == 2 && dhcp[0].Contains("source=dhcp"), "DHCP commands");
            var stat = NetworkChanger.BuildCommands(new ChangeRequest { Adapter = "Ethernet", Address = "10.0.0.2", Mask = "255.255.255.0", Gateway = "10.0.0.1", Dns1 = "1.1.1.1", Dns2 = "8.8.8.8" });
            failures += Check(stat.Count == 3 && stat[2].Contains("index=2"), "static commands");
            failures += Check(RequestValidator.Validate(new ChangeRequest { Adapter = "Ethernet", Operation = "release" }) == null, "valid DHCP release request");
            failures += Check(NetworkChanger.BuildIpconfigArguments(new ChangeRequest { Adapter = "Ethernet", Operation = "renew" }) == "/renew \"Ethernet\"", "DHCP renew command");
            failures += Check(RequestValidator.Validate(new ChangeRequest { Operation = "flushdns" }) == null, "valid DNS flush request");
            failures += Check(NetworkChanger.BuildIpconfigArguments(new ChangeRequest { Operation = "flushdns" }) == "/flushdns", "DNS flush command");
            failures += Check(NmapSupport.ValidateTarget("192.168.1.0/24") == null, "valid Nmap CIDR target");
            failures += Check(NmapSupport.ValidateTarget("-iL file.txt") != null, "reject Nmap option injection");
            failures += Check(NmapSupport.ArgumentsFor(1, "router.local").Contains("--top-ports 100"), "Nmap quick scan preset");
            failures += Check(NmapSupport.ArgumentsFor(0, "192.168.1.0/24", "eth4").Contains("-e eth4"), "Nmap adapter argument");
            var interfaceMap = NmapSupport.ParseInterfaceMap("eth4   \\Device\\NPF_{8E11A7AA-6A36-4998-9B3B-7DED87E0E3AC}\r\n");
            failures += Check(interfaceMap.ContainsKey("8E11A7AA-6A36-4998-9B3B-7DED87E0E3AC") && interfaceMap["8E11A7AA-6A36-4998-9B3B-7DED87E0E3AC"] == "eth4", "map Windows adapter to Nmap interface");
            failures += Check(NmapSupport.NetworkTarget("192.168.8.42", "255.255.255.0") == "192.168.8.0/24", "derive Nmap network target");
            failures += Check(NmapSupport.NetworkTarget("10.20.31.4", "255.255.240.0") == "10.20.16.0/20", "derive non-/24 network target");
            failures += Check(PingSupport.ValidateTarget("router.local") == null, "valid ping hostname");
            failures += Check(PingSupport.ValidateTarget("192.168.1.0/24") != null, "reject ping network range");
            failures += Check(PingSupport.ArgumentsFor("192.168.1.1", true) == "-t 192.168.1.1", "continuous ping arguments");
            failures += Check(PingSupport.ArgumentsFor("192.168.1.1", false, "192.168.1.10") == "-n 4 -S 192.168.1.10 192.168.1.1", "ping adapter binding");
            failures += Check(ConnectionSupport.ValidateHost("router.local") == null, "valid SSH host");
            failures += Check(ConnectionSupport.ValidateUsername("lab-admin") == null, "valid SSH username");
            failures += Check(ConnectionSupport.ValidateUsername("name & command") != null, "reject SSH username injection");
            failures += Check(ConnectionSupport.BuildClientArguments(true, "192.168.1.1", 2222, "admin") == "-p 2222 admin@192.168.1.1", "SSH client arguments");
            failures += Check(ConnectionSupport.BuildClientArguments(true, "192.168.1.1", 22, "admin", "192.168.1.10") == "-b 192.168.1.10 -p 22 admin@192.168.1.1", "SSH adapter binding");
            failures += Check(ConnectionSupport.BuildClientArguments(false, "192.168.1.1", 23, "") == "192.168.1.1 23", "Telnet client arguments");
            Console.WriteLine(failures == 0 ? "All self-tests passed." : failures + " self-test(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static int Check(bool condition, string name)
        {
            if (condition) { Console.WriteLine("PASS " + name); return 0; }
            Console.WriteLine("FAIL " + name); return 1;
        }
    }
}
