using System.Windows;

namespace PersistenceAuditor
{
    /// <summary>
    /// Interaction logic for SplashScreen.xaml
    /// </summary>
    public partial class SplashScreen : Window
    {
        public SplashScreen()
        {
            InitializeComponent();
        }

        private void BtnGetStarted_Click(object sender, RoutedEventArgs e)
        {
            // Lock the button to prevent double-instantiation
            BtnGetStarted.IsEnabled = false;
            BtnGetStarted.Content = "INITIALIZING...";

            // Instantiate the primary application interface
            MainWindow mainInterface = new MainWindow();

            // Display the primary interface
            mainInterface.Show();

            // Terminate the splash screen window to release allocated memory
            this.Close();
        }
    }
}