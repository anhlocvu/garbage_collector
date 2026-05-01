use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;
use winreg::enums::*;
use winreg::RegKey;

use windows_sys::Win32::System::ProcessStatus::{EnumProcesses, K32EmptyWorkingSet};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_QUERY_INFORMATION};
use windows_sys::Win32::Foundation::CloseHandle;
use std::mem;

pub struct JunkItem {
    pub path: PathBuf,
    pub size: u64,
}

pub fn get_junk_directories() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // 1. User Temp: %TEMP%
    if let Ok(temp) = env::var("TEMP") {
        dirs.push(PathBuf::from(temp));
    }

    // 2. User Recent: %APPDATA%\Microsoft\Windows\Recent
    if let Ok(appdata) = env::var("APPDATA") {
        let recent = Path::new(&appdata).join("Microsoft").join("Windows").join("Recent");
        if recent.exists() {
            dirs.push(recent);
        }
    }

    // 3. Local AppData CrashDumps: %LOCALAPPDATA%\CrashDumps
    if let Ok(localappdata) = env::var("LOCALAPPDATA") {
        let local_appdata_path = Path::new(&localappdata);
        
        let crash_dumps = local_appdata_path.join("CrashDumps");
        if crash_dumps.exists() { dirs.push(crash_dumps); }

        // Browser Caches
        let chrome_cache = local_appdata_path.join(r"Google\Chrome\User Data\Default\Cache\Cache_Data");
        if chrome_cache.exists() { dirs.push(chrome_cache); }
        
        let chrome_sys_cache = local_appdata_path.join(r"Google\Chrome\User Data\Default\System Cache\Cache_Data");
        if chrome_sys_cache.exists() { dirs.push(chrome_sys_cache); }

        let edge_cache = local_appdata_path.join(r"Microsoft\Edge\User Data\Default\Cache\Cache_Data");
        if edge_cache.exists() { dirs.push(edge_cache); }
        
        // Firefox Caches (might have multiple profiles, we grab the root Cache folder if possible,
        // or walk the Profiles directory for 'cache2'). Let's add the Profiles dir to scan.
        let firefox_profiles = local_appdata_path.join(r"Mozilla\Firefox\Profiles");
        if firefox_profiles.exists() {
            // We just add the parent profile cache dir, we won't delete the profile itself 
            // since our scan_directory deletes contents. 
            // WAIT, deleting contents of Firefox Profiles will wipe user data! We must only target 'cache2'.
            if let Ok(entries) = fs::read_dir(&firefox_profiles) {
                for entry in entries.filter_map(Result::ok) {
                    let cache2 = entry.path().join("cache2");
                    if cache2.exists() {
                        dirs.push(cache2);
                    }
                }
            }
        }
    }

    // System directories (Requires Admin)
    let win_temp = PathBuf::from(r"C:\Windows\Temp");
    if win_temp.exists() { dirs.push(win_temp); }

    let win_prefetch = PathBuf::from(r"C:\Windows\Prefetch");
    if win_prefetch.exists() { dirs.push(win_prefetch); }

    let wu_download = PathBuf::from(r"C:\Windows\SoftwareDistribution\Download");
    if wu_download.exists() { dirs.push(wu_download); }
    
    // System Logs
    let win_logs = PathBuf::from(r"C:\Windows\Logs");
    if win_logs.exists() { dirs.push(win_logs); }

    let sys32_logs = PathBuf::from(r"C:\Windows\System32\LogFiles");
    if sys32_logs.exists() { dirs.push(sys32_logs); }

    dirs
}

pub fn scan_directory(dir: &Path) -> Vec<JunkItem> {
    let mut items = Vec::new();

    // We only want to delete the contents of the target directory, not the directory itself.
    // Use contents_first(true) so we process (and later delete) children before their parents.
    for entry in WalkDir::new(dir).min_depth(1).contents_first(true) {
        if let Ok(entry) = entry {
            let path = entry.path().to_path_buf();
            
            // Try to get metadata to get size
            if let Ok(metadata) = entry.metadata() {
                let size = if metadata.is_file() {
                    metadata.len()
                } else {
                    0 // Directories have minimal size, usually counted as 0 for junk
                };

                items.push(JunkItem { path, size });
            } else {
                // Cannot access metadata (maybe permission denied even as admin, or file locked)
                // Still add it with 0 size to attempt deletion
                 items.push(JunkItem { path, size: 0 });
            }
        }
    }

    items
}

pub fn delete_item(path: &Path) -> Result<(), std::io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

pub fn run_disk_cleanup() {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cache_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches";
    
    if let Ok(caches) = hklm.open_subkey_with_flags(cache_path, KEY_READ | KEY_WRITE) {
        for key_name in caches.enum_keys().filter_map(|k| k.ok()) {
            if let Ok(subkey) = caches.open_subkey_with_flags(&key_name, KEY_WRITE) {
                // Set StateFlags0001 to 2 to automatically check this item in cleanmgr /sagerun:1
                let _ = subkey.set_value("StateFlags0001", &2u32);
            }
        }
    }

    // Run cleanmgr.exe /sagerun:1 and wait for it to finish.
    let _ = Command::new("cleanmgr.exe")
        .arg("/sagerun:1")
        .status();
}

pub fn optimize_ram() {
    // Also clear DNS cache to help network performance and free up some system cache
    let _ = Command::new("ipconfig").arg("/flushdns").status();

    unsafe {
        let mut processes = [0u32; 1024];
        let mut bytes_returned = 0;
        if EnumProcesses(
            processes.as_mut_ptr(),
            (mem::size_of::<u32>() * processes.len()) as u32,
            &mut bytes_returned,
        ) != 0
        {
            let count = bytes_returned as usize / mem::size_of::<u32>();
            for i in 0..count {
                let pid = processes[i];
                if pid != 0 {
                    let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, 0, pid);
                    if handle != std::ptr::null_mut() {
                        K32EmptyWorkingSet(handle);
                        CloseHandle(handle);
                    }
                }
            }
        }
    }
}
