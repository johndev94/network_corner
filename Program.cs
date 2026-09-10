using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Security.Principal;
using System.Text;
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

    internal sealed class ChangeRequest
    {
        public string Adapter { get; set; }
        public bool Dhcp { get; set; }
        public string Address { get; set; }
        public string Mask { get; set; }
        public string Gateway { get; set; }
        public string Dns1 { get; set; }
        public string Dns2 { get; set; }
    }

    internal sealed class AdapterInfo
    {
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

    internal static class NetworkReader
    {
        public static List<AdapterInfo> GetAdapters()
        {
            var result = new List<AdapterInfo>();
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!IsUseful(nic)) continue;
                var item = new AdapterInfo();
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
            if (String.IsNullOrWhiteSpace(request.Adapter)) return "Choose a network adapter.";
            if (request.Adapter.IndexOf('"') >= 0 || request.Adapter.IndexOf('\r') >= 0 || request.Adapter.IndexOf('\n') >= 0)
                return "The adapter name contains unsupported characters.";
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
                MessageBox.Show(request.Dhcp ? "DHCP is now enabled." : "The static network settings were applied.", "Network Corner", MessageBoxButtons.OK, MessageBoxIcon.Information);
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

        private static void Apply(ChangeRequest request)
        {
            if (!IsAdministrator()) throw new InvalidOperationException("Administrator permission is required to change network settings.");
            foreach (string command in BuildCommands(request)) RunNetsh(command);
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

    internal sealed class MainForm : Form
    {
        private readonly Color Back = Color.FromArgb(20, 25, 32);
        private readonly Color Panel = Color.FromArgb(30, 37, 47);
        private readonly Color Muted = Color.FromArgb(157, 170, 187);
        private readonly Color Accent = Color.FromArgb(51, 182, 161);
        private readonly Font summaryRegularFont = new Font("Consolas", 9F, FontStyle.Regular);
        private readonly Font summaryBoldFont = new Font("Consolas", 9F, FontStyle.Bold);
        private readonly ComboBox adapterBox = new ComboBox();
        private readonly ComboBox profileBox = new ComboBox();
        private readonly ComboBox screenBox = new ComboBox();
        private readonly ComboBox cornerBox = new ComboBox();
        private readonly CheckBox fullHeightCheck = new CheckBox();
        private readonly TextBox addressBox = new TextBox();
        private readonly TextBox maskBox = new TextBox();
        private readonly TextBox gatewayBox = new TextBox();
        private readonly TextBox dns1Box = new TextBox();
        private readonly TextBox dns2Box = new TextBox();
        private readonly RichTextBox summaryBox = new RichTextBox();
        private readonly Label updatedLabel = new Label();
        private readonly Timer refreshTimer = new Timer();
        private List<AdapterInfo> adapters = new List<AdapterInfo>();
        private List<NetworkProfile> profiles = new List<NetworkProfile>();
        private bool loading;
        private int normalHeight;
        private readonly string profilePath;

        public MainForm()
        {
            profilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkCorner", "profiles.json");
            Text = "Network Corner";
            ClientSize = new Size(410, 780);
            MinimumSize = new Size(390, 650);
            BackColor = Back;
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 9F);
            TopMost = true;
            FormBorderStyle = FormBorderStyle.SizableToolWindow;
            StartPosition = FormStartPosition.Manual;
            ShowInTaskbar = true;

            BuildUi();
            LoadProfiles();
            LoadScreens();
            RefreshAdapters(true);
            refreshTimer.Interval = 5000;
            refreshTimer.Tick += delegate { RefreshAdapters(false); };
            refreshTimer.Start();
            Shown += delegate { normalHeight = Height; DockToCorner(); };
            FormClosed += delegate { summaryRegularFont.Dispose(); summaryBoldFont.Dispose(); };
        }

        private void BuildUi()
        {
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(14), ColumnCount = 1, RowCount = 5, BackColor = Back };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 340));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
            Controls.Add(root);

            var titlePanel = new Panel { Dock = DockStyle.Fill };
            var title = new Label { Text = "NETWORK CORNER", Font = new Font("Segoe UI Semibold", 14F), AutoSize = true, Location = new Point(0, 2), ForeColor = Color.White };
            updatedLabel.Text = "Checking adapters…";
            updatedLabel.AutoSize = true;
            updatedLabel.Location = new Point(2, 29);
            updatedLabel.ForeColor = Muted;
            titlePanel.Controls.Add(title);
            titlePanel.Controls.Add(updatedLabel);
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
            screenBox.SelectedIndexChanged += delegate { DockToCorner(); };
            cornerBox.SelectedIndexChanged += delegate { DockToCorner(); };
            location.Controls.Add(screenBox);
            location.Controls.Add(cornerBox);
            editor.Controls.Add(FieldLabel("POSITION"), 0, 7);
            editor.Controls.Add(location, 1, 7);

            fullHeightCheck.Text = "Stretch panel to full monitor height";
            fullHeightCheck.Dock = DockStyle.Fill;
            fullHeightCheck.ForeColor = Color.White;
            fullHeightCheck.CheckedChanged += delegate { DockToCorner(); };
            editor.Controls.Add(FieldLabel("DISPLAY"), 0, 8);
            editor.Controls.Add(fullHeightCheck, 1, 8);
            root.Controls.Add(editor, 0, 3);

            var actions = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, Padding = new Padding(0, 10, 0, 0), BackColor = Back };
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20));
            actions.Controls.Add(MakeButton("Apply static", delegate { Apply(false); }, true, 0), 0, 0);
            actions.Controls.Add(MakeButton("Use DHCP", delegate { Apply(true); }, false, 0), 1, 0);
            actions.Controls.Add(MakeButton("↻", delegate { RefreshAdapters(true); }, false, 0), 2, 0);
            root.Controls.Add(actions, 0, 4);
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
            adapters = NetworkReader.GetAdapters();
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
            loading = false;
            if (populate) PopulateFields();
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
            if (a == null) return;
            addressBox.Text = a.Address;
            maskBox.Text = a.Mask;
            gatewayBox.Text = a.Gateway;
            dns1Box.Text = a.Dns1;
            dns2Box.Text = a.Dns2;
            profileBox.SelectedIndex = -1;
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
                MessageBox.Show(validation, "Check network settings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string action = dhcp ? "switch " + request.Adapter + " to DHCP" : "apply these static settings to " + request.Adapter;
            if (MessageBox.Show("This will " + action + ". Connectivity may briefly drop. Continue?", "Confirm network change", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

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
                if (ex.NativeErrorCode != 1223) MessageBox.Show(ex.Message, "Could not start network change", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Could not start network change", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }
        }

        private void LoadProfiles()
        {
            try
            {
                if (File.Exists(profilePath)) profiles = new JavaScriptSerializer().Deserialize<List<NetworkProfile>>(File.ReadAllText(profilePath, Encoding.UTF8)) ?? new List<NetworkProfile>();
            }
            catch { profiles = new List<NetworkProfile>(); }
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
            string name = Prompt.Show("Profile name", "Save network profile");
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
            if (MessageBox.Show("Delete profile ‘" + name + "’?", "Delete profile", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
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
        public static string Show(string label, string title)
        {
            using (var form = new Form())
            using (var input = new TextBox())
            using (var ok = new Button())
            using (var cancel = new Button())
            {
                form.Text = title; form.ClientSize = new Size(330, 112); form.FormBorderStyle = FormBorderStyle.FixedDialog; form.StartPosition = FormStartPosition.CenterParent; form.MinimizeBox = false; form.MaximizeBox = false;
                var prompt = new Label { Text = label, Left = 12, Top = 12, Width = 300 };
                input.Left = 12; input.Top = 35; input.Width = 306;
                ok.Text = "Save"; ok.Left = 162; ok.Top = 72; ok.Width = 75; ok.DialogResult = DialogResult.OK;
                cancel.Text = "Cancel"; cancel.Left = 243; cancel.Top = 72; cancel.Width = 75; cancel.DialogResult = DialogResult.Cancel;
                form.Controls.AddRange(new Control[] { prompt, input, ok, cancel }); form.AcceptButton = ok; form.CancelButton = cancel;
                return form.ShowDialog() == DialogResult.OK ? input.Text : null;
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
