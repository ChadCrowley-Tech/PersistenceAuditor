using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Controls;

namespace PersistenceAuditor
{
    public partial class MainWindow : Window
    {
        // This collection automatically updates the UI when items are added or removed
        public ObservableCollection<ThreatArtifact> HuntResults { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            HuntResults = new ObservableCollection<ThreatArtifact>();
            GridThreats.ItemsSource = HuntResults; // Binds the DataGrid to the collection
        }

        // ==========================================
        // UI INTERACTION LOGIC
        // ==========================================

        private async void BtnStartHunt_Click(object sender, RoutedEventArgs e)
        {
            BtnStartHunt.Content = "SCANNING...";
            BtnStartHunt.IsEnabled = false;

            // Clears previous results
            HuntResults.Clear();

            // Runs the scans on a background thread so the UI doesn't freeze
            var liveResults = await System.Threading.Tasks.Task.Run(() =>
            {
                var combinedResults = new System.Collections.Generic.List<ThreatArtifact>();

                // MITRE T1547.001
                combinedResults.AddRange(Engines.RegistryScanner.ScanRunKeys());

                // MITRE T1053.005
                combinedResults.AddRange(Engines.ScheduledTaskScanner.ScanTasks());

                // MITRE T1543.003
                combinedResults.AddRange(Engines.ServiceScanner.ScanServices());

                return combinedResults;
            });

            // Populates the UI DataGrid with the live results
            foreach (var artifact in liveResults)
            {
                HuntResults.Add(artifact);
            }

            BtnStartHunt.Content = "SCAN COMPLETE";
            BtnStartHunt.IsEnabled = true;
            BtnExportHunt.IsEnabled = true;
        }

        private async void BtnExportHunt_Click(object sender, RoutedEventArgs e)
        {
            if (HuntResults.Count == 0) return;

            BtnExportHunt.IsEnabled = false;
            string originalText = BtnExportHunt.Content.ToString();
            BtnExportHunt.Content = "COPYING...";

            string exportData = "PERSISTENCE AUDITOR: THREAT TELEMETRY\n";
            exportData += $"Scan Time: {DateTime.Now}\n";
            exportData += $"Total Artifacts Logged: {HuntResults.Count}\n\n";

            foreach (var artifact in HuntResults)
            {
                exportData += $"[SEVERITY]: {artifact.Severity}\n";
                exportData += $"[CATEGORY]: {artifact.Category}\n";
                exportData += $"[NAME]: {artifact.Name}\n";
                exportData += $"[PATH]: {artifact.Path}\n";
                exportData += "--------------------------------------------------\n";
            }

            Clipboard.SetText(exportData);

            // Brief visual feedback
            BtnExportHunt.Content = "COPIED TO CLIPBOARD";
            await System.Threading.Tasks.Task.Delay(2000); // 2 second delay

            BtnExportHunt.Content = originalText;
            BtnExportHunt.IsEnabled = true;
        }

        private void GridThreats_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (GridThreats.SelectedItem is ThreatArtifact selectedArtifact)
            {
                TxtDetailName.Text = $"[{selectedArtifact.Category}] {selectedArtifact.Name}";
                TxtDetailPath.Text = selectedArtifact.Path;

                // Only enables the delete button if it's not a verified baseline system file
                BtnRemediate.IsEnabled = selectedArtifact.Severity != "BASELINE";
            }
        }

        private async void BtnRemediate_Click(object sender, RoutedEventArgs e)
        {
            if (GridThreats.SelectedItem is ThreatArtifact selectedArtifact)
            {
                // Strict Analyst Confirmation
                MessageBoxResult confirmation = MessageBox.Show(
                    $"WARNING: You are about to permanently delete the following persistence mechanism:\n\n" +
                    $"Name: {selectedArtifact.Name}\n" +
                    $"Path: {selectedArtifact.Path}\n\n" +
                    $"Are you absolutely sure you want to proceed?",
                    "Confirm Threat Deletion", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (confirmation == MessageBoxResult.No) return;

                BtnRemediate.Content = "EXECUTING PURGE...";
                BtnRemediate.IsEnabled = false;

                string payload = "";

                // Build the dynamic payload based on the Artifact Category
                if (selectedArtifact.Category.Contains("Scheduled Task"))
                {
                    payload = $"Unregister-ScheduledTask -TaskName '{selectedArtifact.Name}' -Confirm:$false";
                }
                else if (selectedArtifact.Category.Contains("Run Key"))
                {
                    string root = selectedArtifact.Category.Contains("HKLM") ? "HKLM:" : "HKCU:";
                    string subKey = selectedArtifact.Category.Contains("RunOnce")
                        ? @"\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                        : @"\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

                    payload = $"Remove-ItemProperty -Path '{root}{subKey}' -Name '{selectedArtifact.Name}' -Force -ErrorAction SilentlyContinue";
                }

                // Execute the payload elevated
                bool success = await ExecuteRemediationAsync(payload);

                if (success)
                {
                    MessageBox.Show("Artifact successfully purged from the system.", "Remediation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                    HuntResults.Remove(selectedArtifact); // Remove it from the UI grid
                }
                else
                {
                    MessageBox.Show("Execution failed. The artifact may be protected by the system or require manual removal.", "Remediation Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                }

                BtnRemediate.Content = "DELETE ARTIFACT";
            }
        }

        /// <summary>
        /// Local helper to securely execute the PowerShell deletion payload.
        /// </summary>
        private async System.Threading.Tasks.Task<bool> ExecuteRemediationAsync(string payload)
        {
            string encodedCommand = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(payload));

            System.Diagnostics.ProcessStartInfo processInfo = new System.Diagnostics.ProcessStartInfo()
            {
                FileName = "powershell",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encodedCommand}",
                UseShellExecute = true,
                Verb = "runas", // Forces the UAC prompt for Administrative rights
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
            };

            try
            {
                using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(processInfo))
                {
                    await System.Threading.Tasks.Task.Run(() => process.WaitForExit());
                    return process.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        // ==========================================
        // WINDOW CHROME LOGIC
        // ==========================================

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left) this.DragMove();
        }

        private void BtnMinimize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void BtnMaximize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = this.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }

    // ==========================================
    // DATA MODEL
    // ==========================================
    public class ThreatArtifact
    {
        public string Severity { get; set; }
        public string Category { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string Status { get; set; }
    }
}