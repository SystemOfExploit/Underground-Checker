using MR_Cleaner.Utility;
using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MR_Cleaner.Forms
{
    public partial class FormRAM : MetroFramework.Forms.MetroForm
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct MemoryStatus
        {
            public uint Length;
            public uint MemoryLoad;
            public ulong TotalPhysical;
            public ulong AvailablePhysical;
            public ulong TotalPageFile;
            public ulong AvailablePageFile;
            public ulong TotalVirtual;
            public ulong AvailableVirtual;
            public ulong AvailableExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx(ref MemoryStatus memoryStatus);

        private Timer _updateTimer;
        private bool _isRefreshing;

        public FormRAM()
        {
            InitializeComponent();
            ActiveControl = null;
        }

        private void FormRAM_Load(object sender, EventArgs e)
        {
            SetLabelColors();
            RefreshRamInfo();
            _updateTimer = new Timer { Interval = 1500 };
            _updateTimer.Tick += UpdateTimer_Tick;
            _updateTimer.Start();
            ActiveControl = null;
        }

        private void SetLabelColors()
        {
            foreach (MetroFramework.Controls.MetroLabel label in new[] { ramLabel, usedMbLabel, totalMbLabel })
            {
                label.ForeColor = Color.White;
                label.UseCustomForeColor = true;
            }
        }

        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            RefreshRamInfo();
        }

        private void RefreshRamInfo()
        {
            if (_isRefreshing || !TryGetMemoryStatus(out MemoryStatus status))
                return;

            _isRefreshing = true;
            try
            {
                ulong used = status.TotalPhysical - status.AvailablePhysical;
                long totalMb = (long)(status.TotalPhysical / 1024 / 1024);
                long usedMb = (long)(used / 1024 / 1024);
                long freeMb = (long)(status.AvailablePhysical / 1024 / 1024);
                ramLabel.Text = string.Format("Общая нагрузка ОЗУ: {0}%", status.MemoryLoad);
                usedMbLabel.Text = string.Format("Используется: {0:N0} MB | Свободно: {1:N0} MB", usedMb, freeMb);
                totalMbLabel.Text = string.Format("Всего памяти: {0:N0} MB", totalMb);
            }
            finally
            {
                _isRefreshing = false;
            }
        }

        private static bool TryGetMemoryStatus(out MemoryStatus status)
        {
            status = new MemoryStatus { Length = (uint)Marshal.SizeOf(typeof(MemoryStatus)) };
            return GlobalMemoryStatusEx(ref status);
        }

        private async void cleanButton_Click(object sender, EventArgs e)
        {
            if (MetroFramework.MetroMessageBox.Show(this, "Действительно очистить рабочие наборы памяти?", "MemReduct", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            cleanButton.Enabled = false;
            try
            {
                var cleaner = new MemReduct();
                await Task.Run(() => cleaner.CleanMemory(includeSystem: false, cleanFileCache: true));
                await Task.Delay(250);
                RefreshRamInfo();
                MetroFramework.MetroMessageBox.Show(this, cleaner.GetSummary(), "MemReduct", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MetroFramework.MetroMessageBox.Show(this, "Не удалось очистить память: " + ex.Message, "MemReduct", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                cleanButton.Enabled = true;
                ActiveControl = null;
            }
        }

        protected override void OnActivated(EventArgs e)
        {
            base.OnActivated(e);
            ActiveControl = null;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (_updateTimer != null)
            {
                _updateTimer.Stop();
                _updateTimer.Tick -= UpdateTimer_Tick;
                _updateTimer.Dispose();
                _updateTimer = null;
            }
            base.OnFormClosing(e);
        }
    }
}
