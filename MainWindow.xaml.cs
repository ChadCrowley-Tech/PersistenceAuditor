using PersistenceAuditor.Interfaces;
using PersistenceAuditor.Reporters;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

namespace PersistenceAuditor
{
    public partial class MainWindow : Window
    {
        // Observable collection to automatically trigger UI updates upon data mutation
        public ObservableCollection<ThreatArtifact> HuntResults { get; set; }

        // View wrapper to manage real-time UI filtering and visibility
        private ICollectionView _threatsView;

        // The active reporting engine, accessed via the interface contract
        private IIncidentReporter _activeReporter;

        public MainWindow()
        {
            InitializeComponent();
            HuntResults = new ObservableCollection<ThreatArtifact>();
            GridThreats.ItemsSource = HuntResults; // Binds the DataGrid to the collection

            // Initialize the collection view and assign the filtering predicate
            _threatsView = CollectionViewSource.GetDefaultView(HuntResults);
            _threatsView.Filter = FilterThreats;

            _activeReporter = new LocalJsonReporter();

        }

        // ==========================================
        // UI INTERACTION LOGIC
        // ==========================================

        private async void BtnStartHunt_Click(object sender, RoutedEventArgs e)
        {
            BtnStartHunt.Content = "SCANNING...";
            BtnStartHunt.IsEnabled = false;

            // Force the engine to read the latest JSON whitelist from disk
            Engines.HeuristicEngine.ReloadConfiguration();

            // Clears previous results
            HuntResults.Clear();

            // Execute scans on a background thread to prevent UI blocking
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

            // Populate the UI DataGrid with the live results
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

            foreach (ThreatArtifact artifact in _threatsView)
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

                // Enable the remediation button only for non-baseline artifacts
                BtnRemediate.IsEnabled = selectedArtifact.Severity != "BASELINE";

                // Enable the dispatch button whenever any valid artifact is selected
                BtnDispatch.IsEnabled = true;
            }
            else
            {
                BtnDispatch.IsEnabled = false;
            }
        }

        private bool FilterThreats(object obj)
        {
            if (obj is ThreatArtifact artifact)
            {
                // Evaluate the severity filter selection
                if (CmbSeverityFilter != null && CmbSeverityFilter.SelectedItem is ComboBoxItem selectedItem)
                {
                    // Convert the readable UI text to uppercase for comparison
                    string severitySelection = selectedItem.Content.ToString().ToUpper();

                    // Enforce exact match unless the default "All Severities" bypass is active
                    if (!severitySelection.Contains("ALL"))
                    {
                        // Check if the UI dropdown text contains the artifact's exact backend severity code
                        if (string.IsNullOrEmpty(artifact.Severity) || !severitySelection.Contains(artifact.Severity.ToUpper()))
                        {
                            return false;
                        }
                    }
                }

                // Evaluate text search filter against name, path, and category fields
                string searchText = TxtSearch.Text.Trim().ToLower();
                if (!string.IsNullOrEmpty(searchText))
                {
                    bool matchesName = artifact.Name?.ToLower().Contains(searchText) ?? false;
                    bool matchesPath = artifact.Path?.ToLower().Contains(searchText) ?? false;
                    bool matchesCategory = artifact.Category?.ToLower().Contains(searchText) ?? false;

                    // Exclude item if text search criteria are not met
                    if (!matchesName && !matchesPath && !matchesCategory)
                    {
                        return false;
                    }
                }

                // Include item if all filter criteria are met
                return true;
            }

            return false;
        }

        private async void BtnRemediate_Click(object sender, RoutedEventArgs e)
        {
            if (GridThreats.SelectedItem is ThreatArtifact selectedArtifact)
            {
                // Strict analyst confirmation prompt
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

                // Build the dynamic payload based on the artifact category
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
                else if (selectedArtifact.Category.Contains("Service"))
                {
                    // Force cmd.exe to handle the sc.exe command to avoid PowerShell quote stripping
                    payload = $"Stop-Service -Name '{selectedArtifact.Name}' -Force -ErrorAction SilentlyContinue; cmd.exe /c sc delete \"{selectedArtifact.Name}\"";
                }

                // Execute the payload with elevated privileges
                bool success = await ExecuteRemediationAsync(payload);

                if (success)
                {
                    MessageBox.Show("Artifact successfully purged from the system.", "Remediation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                    HuntResults.Remove(selectedArtifact); // Remove the purged artifact from the UI grid
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
                Verb = "runas", // Forces the UAC prompt for administrative rights
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

        private async void BtnDispatch_Click(object sender, RoutedEventArgs e)
        {
            if (GridThreats.SelectedItem is ThreatArtifact selectedArtifact && _activeReporter != null)
            {
                BtnDispatch.IsEnabled = false;
                string originalText = BtnDispatch.Content.ToString();
                BtnDispatch.Content = "DISPATCHING...";

                // Fire the payload using the interface contract
                bool success = await _activeReporter.ReportIncidentAsync(selectedArtifact);

                if (success)
                {
                    MessageBox.Show("Incident successfully dispatched via active routing mode.", "Dispatch Confirmed", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("Failed to dispatch incident. Verify your network connection or local file permissions.", "Dispatch Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }

                BtnDispatch.Content = originalText;
                BtnDispatch.IsEnabled = true;
            }
        }

        private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Toggle the visibility of the placeholder text
            if (TxtSearchPlaceholder != null)
            {
                TxtSearchPlaceholder.Visibility = string.IsNullOrEmpty(TxtSearch.Text) ? Visibility.Visible : Visibility.Hidden;
            }

            // Trigger the ICollectionView to re-evaluate the filter logic immediately
            _threatsView?.Refresh();
        }

        private void CmbSeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _threatsView?.Refresh();
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

        // ==========================================
        // REPORTER ROUTING LOGIC
        // ==========================================

        private readonly string _settingsFile = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "AppSettings.json");

        private async void ChkRoutingMode_Checked(object sender, RoutedEventArgs e)
        {
            // Dim Local Audit, highlight API Dispatch
            if (TxtLocalAudit != null && TxtApiDispatch != null)
            {
                TxtLocalAudit.Foreground = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#55516B"));
                TxtLocalAudit.Effect = null;

                TxtApiDispatch.Foreground = (System.Windows.Media.Brush)Application.Current.Resources["ColorNetwork"];
                TxtApiDispatch.Effect = new System.Windows.Media.Effects.DropShadowEffect { Color = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00FFFF"), BlurRadius = 12, ShadowDepth = 0, Opacity = 0.8 };
            }

            // Yield to the UI thread for 150ms so the toggle animation renders before the dialog blocks the thread
            await System.Threading.Tasks.Task.Delay(150);

            string activeUrl = string.Empty;

            // Attempt to load previously saved configuration
            if (File.Exists(_settingsFile))
            {
                try
                {
                    string json = File.ReadAllText(_settingsFile);
                    var settings = JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, string>>(json);
                    if (settings != null && settings.ContainsKey("ApiEndpointUrl"))
                    {
                        activeUrl = settings["ApiEndpointUrl"];
                    }
                }
                catch { /* Fails silently and prompts for new input */ }
            }

            // If no URL is saved, prompt for new URL via the custom dialog
            if (string.IsNullOrEmpty(activeUrl))
            {
                ApiConfigWindow configDialog = new ApiConfigWindow();
                configDialog.Owner = this; // Centers the popup over the main window

                if (configDialog.ShowDialog() == true)
                {
                    activeUrl = configDialog.ConfiguredUrl;

                    // Serialize and save the configuration if requested
                    if (configDialog.SaveConfiguration)
                    {
                        var settings = new System.Collections.Generic.Dictionary<string, string>
                        {
                            { "ApiEndpointUrl", activeUrl }
                        };
                        File.WriteAllText(_settingsFile, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
                    }
                }
                else
                {
                    // Dialog canceled; revert the UI toggle to Local Mode
                    ChkRoutingMode.IsChecked = false;
                    return;
                }
            }

            // Instantiate the REST reporter with the acquired URL
            _activeReporter = new HttpRestReporter(activeUrl);
        }

        private void ChkRoutingMode_Unchecked(object sender, RoutedEventArgs e)
        {
            // Dim API Dispatch, highlight Local Audit
            if (TxtLocalAudit != null && TxtApiDispatch != null)
            {
                TxtApiDispatch.Foreground = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#55516B"));
                TxtApiDispatch.Effect = null;

                TxtLocalAudit.Foreground = (System.Windows.Media.Brush)Application.Current.Resources["ColorNetwork"];
                TxtLocalAudit.Effect = new System.Windows.Media.Effects.DropShadowEffect { Color = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00FFFF"), BlurRadius = 12, ShadowDepth = 0, Opacity = 0.8 };
            }

            // Revert back to local file logging
            _activeReporter = new LocalJsonReporter();
        
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

        private string _path;
        public string Path
        {
            get { return _path; }
            set { _path = Environment.ExpandEnvironmentVariables(value); }
        }
        public string Status { get; set; }
    }

}