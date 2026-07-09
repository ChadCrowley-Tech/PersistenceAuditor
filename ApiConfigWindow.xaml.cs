using System;
using System.Windows;

namespace PersistenceAuditor
{
    public partial class ApiConfigWindow : Window
    {
        public string ConfiguredUrl { get; private set; }
        public bool SaveConfiguration { get; private set; }

        public ApiConfigWindow()
        {
            InitializeComponent();
        }

        private void BtnConfirm_Click(object sender, RoutedEventArgs e)
        {
            string url = TxtEndpointUrl.Text.Trim();

            // Validates that the input is a properly structured HTTP/HTTPS URI
            if (Uri.TryCreate(url, UriKind.Absolute, out Uri uriResult) &&
                (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps))
            {
                ConfiguredUrl = url;
                SaveConfiguration = ChkSaveConfig.IsChecked ?? false;
                this.DialogResult = true; // Signals success to the calling window
                this.Close();
            }
            else
            {
                MessageBox.Show("Please enter a valid HTTP or HTTPS URL.", "Invalid Format", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false; // Signals cancellation
            this.Close();
        }
    }
}
