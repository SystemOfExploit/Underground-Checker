using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace MR_Cleaner.Utility
{
    internal static class BotKiller
    {
        private static readonly object SyncRoot = new object();
        private static readonly HashSet<string> SuspiciousNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "xmrig", "xmrig-proxy", "minerd", "cpuminer", "ethminer", "cgminer", "nbminer", "t-rex",
            "mimikatz", "meterpreter", "cobalt", "beacon", "njrat", "quasar", "remcos", "agenttesla"
        };
        private static readonly string[] SuspiciousMarkers =
        {
            "xmrig", "cryptonight", "randomx", "meterpreter", "cobalt", "keylogger", "stealer", "rat"
        };
        private static readonly string[] SuspiciousRoots =
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Temp")
        };

        private static int _processesTerminated;
        private static int _filesDeleted;
        private static readonly List<string> ThreatList = new List<string>();
        private static readonly List<string> TerminatedList = new List<string>();

        public static IReadOnlyList<string> DetectedThreats
        {
            get { lock (SyncRoot) return ThreatList.ToArray(); }
        }

        public static IReadOnlyList<string> TerminatedProcesses
        {
            get { lock (SyncRoot) return TerminatedList.ToArray(); }
        }

        public static int ProcessesTerminated => Volatile.Read(ref _processesTerminated);
        public static int FilesDeleted => Volatile.Read(ref _filesDeleted);
        public static int MutexesDetected => 0;

        public static void ResetStats()
        {
            Interlocked.Exchange(ref _processesTerminated, 0);
            Interlocked.Exchange(ref _filesDeleted, 0);
            lock (SyncRoot)
            {
                ThreatList.Clear();
                TerminatedList.Clear();
            }
        }

        public static void Execute()
        {
            ResetStats();
            RunBotKiller();
        }

        public static void RunBotKiller()
        {
            Process[] processes;
            try { processes = Process.GetProcesses(); }
            catch { return; }

            foreach (Process process in processes)
            {
                try { AnalyzeProcess(process); }
                finally { process.Dispose(); }
            }
        }

        public static string GetReport()
        {
            string[] threats;
            string[] terminated;
            lock (SyncRoot)
            {
                threats = ThreatList.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToArray();
                terminated = TerminatedList.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToArray();
            }

            var lines = new List<string>
            {
                "BotKiller",
                "Обнаружено: " + threats.Length,
                "Завершено процессов: " + ProcessesTerminated,
                "Удалено файлов: " + FilesDeleted
            };

            if (threats.Length > 0)
            {
                lines.Add("Обнаруженные элементы:");
                lines.AddRange(threats);
            }

            if (terminated.Length > 0)
            {
                lines.Add("Завершённые процессы:");
                lines.AddRange(terminated);
            }

            if (threats.Length == 0)
                lines.Add("Подозрительных процессов не обнаружено.");

            return string.Join(Environment.NewLine, lines);
        }

        private static void AnalyzeProcess(Process process)
        {
            if (process == null || process.Id <= 4 || process.Id == Process.GetCurrentProcess().Id)
                return;

            string path;
            string name;
            try
            {
                path = process.MainModule == null ? null : process.MainModule.FileName;
                name = process.ProcessName;
            }
            catch { return; }

            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(name) || IsWindowsPath(path))
                return;

            string reason = GetThreatReason(name, path);
            if (reason == null)
                return;

            string item = string.Format("{0} (PID {1}): {2}; {3}", name, process.Id, reason, path);
            AddThreat(item);

            try
            {
                process.Kill();
                process.WaitForExit(3000);
                Interlocked.Increment(ref _processesTerminated);
                AddTerminated(string.Format("{0} (PID {1})", name, process.Id));
                RemovePersistence(path);
                DeletePayload(path);
            }
            catch (Exception ex)
            {
                AddThreat(item + "; не удалось завершить: " + ex.Message);
            }
        }

        private static string GetThreatReason(string name, string path)
        {
            string fileName = Path.GetFileNameWithoutExtension(path) ?? name;
            bool knownName = SuspiciousNames.Contains(name) || SuspiciousNames.Contains(fileName);
            bool marker = SuspiciousMarkers.Any(x => path.IndexOf(x, StringComparison.OrdinalIgnoreCase) >= 0);
            bool temporaryLocation = SuspiciousRoots.Any(x => !string.IsNullOrWhiteSpace(x) && path.StartsWith(x, StringComparison.OrdinalIgnoreCase));
            bool hidden = IsHidden(path);

            if (knownName)
                return "имя совпало с известным индикатором";
            if (marker && (temporaryLocation || hidden))
                return "индикатор в имени и небезопасное расположение";
            return null;
        }

        private static bool IsWindowsPath(string path)
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            return path.StartsWith(windows, StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsHidden(string path)
        {
            try { return (File.GetAttributes(path) & (FileAttributes.Hidden | FileAttributes.System)) != 0; }
            catch { return false; }
        }

        private static void DeletePayload(string path)
        {
            try
            {
                if (!File.Exists(path) || IsWindowsPath(path))
                    return;
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
                Interlocked.Increment(ref _filesDeleted);
            }
            catch { }
        }

        private static void RemovePersistence(string path)
        {
            RemovePersistence(Registry.CurrentUser, path);
            RemovePersistence(Registry.LocalMachine, path);
        }

        private static void RemovePersistence(RegistryKey hive, string path)
        {
            try
            {
                foreach (string keyPath in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
                using (RegistryKey key = hive.OpenSubKey(keyPath, true))
                {
                    if (key == null) continue;
                    foreach (string valueName in key.GetValueNames())
                    {
                        string value = key.GetValue(valueName) as string;
                        if (!string.IsNullOrWhiteSpace(value) && value.IndexOf(path, StringComparison.OrdinalIgnoreCase) >= 0)
                            key.DeleteValue(valueName, false);
                    }
                }
            }
            catch { }
        }

        private static void AddThreat(string value)
        {
            lock (SyncRoot) ThreatList.Add(value);
        }

        private static void AddTerminated(string value)
        {
            lock (SyncRoot) TerminatedList.Add(value);
        }
    }
}
