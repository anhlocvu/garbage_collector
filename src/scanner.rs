use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::os::windows::process::CommandExt;
use walkdir::WalkDir;
use winreg::enums::*;
use winreg::RegKey;

use windows_sys::Win32::System::ProcessStatus::{EnumProcesses, K32EmptyWorkingSet};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_QUERY_INFORMATION};
use windows_sys::Win32::Foundation::CloseHandle;
use std::mem;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Clone, Debug, PartialEq)]
pub enum JunkType {
    FileOrDir(PathBuf),
    RegistryValue { hkey: isize, subkey: String, value_name: String },
}

#[derive(Clone, Debug)]
pub struct JunkItem {
    pub junk_type: JunkType,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct StartupItem {
    pub name: String,
    pub command: String,
    pub hkey: isize,
    pub subkey: String,
}

#[derive(Clone, Debug)]
pub struct LargeFile {
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
        
        let firefox_profiles = local_appdata_path.join(r"Mozilla\Firefox\Profiles");
        if firefox_profiles.exists() {
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

    for entry in WalkDir::new(dir).min_depth(1).contents_first(true) {
        if let Ok(entry) = entry {
            let path = entry.path().to_path_buf();
            if let Ok(metadata) = entry.metadata() {
                let size = if metadata.is_file() { metadata.len() } else { 0 };
                items.push(JunkItem { junk_type: JunkType::FileOrDir(path), size });
            } else {
                 items.push(JunkItem { junk_type: JunkType::FileOrDir(path), size: 0 });
            }
        }
    }

    items
}

// Registry Cleaner: Finds dead links in Run keys
pub fn scan_dead_registry_keys() -> Vec<JunkItem> {
    let mut dead_keys = Vec::new();
    let run_keys = [
        (HKEY_CURRENT_USER as isize, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_LOCAL_MACHINE as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ];

    for (hkey_val, subkey_path) in run_keys {
        let hkey = RegKey::predef(hkey_val as *mut std::ffi::c_void);
        if let Ok(subkey) = hkey.open_subkey_with_flags(subkey_path, KEY_READ) {
            for val in subkey.enum_values().filter_map(|v| v.ok()) {
                let val_name = val.0;
                let val_data: String = match val.1.to_string() {
                    s if s.is_empty() => continue,
                    s => s,
                };
                
                // Simple extraction of executable path
                let mut path_str = val_data.as_str();
                if path_str.starts_with('"') {
                    if let Some(end) = path_str[1..].find('"') {
                        path_str = &path_str[1..=end];
                    }
                } else {
                    if let Some(end) = path_str.find(" -") {
                        path_str = &path_str[..end];
                    } else if let Some(end) = path_str.find(" /") {
                        path_str = &path_str[..end];
                    }
                }
                
                let p = Path::new(path_str);
                // If the path looks like an absolute path and doesn't exist, it's a dead link
                if p.is_absolute() && !p.exists() {
                    dead_keys.push(JunkItem {
                        junk_type: JunkType::RegistryValue {
                            hkey: hkey_val,
                            subkey: subkey_path.to_string(),
                            value_name: val_name,
                        },
                        size: 0,
                    });
                }
            }
        }
    }
    dead_keys
}

pub fn get_startup_items() -> Vec<StartupItem> {
    let mut items = Vec::new();
    let run_keys = [
        (HKEY_CURRENT_USER as isize, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_LOCAL_MACHINE as isize, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ];

    for (hkey_val, subkey_path) in run_keys {
        let hkey = RegKey::predef(hkey_val as *mut std::ffi::c_void);
        if let Ok(subkey) = hkey.open_subkey_with_flags(subkey_path, KEY_READ) {
            for val in subkey.enum_values().filter_map(|v| v.ok()) {
                items.push(StartupItem {
                    name: val.0.clone(),
                    command: val.1.to_string(),
                    hkey: hkey_val,
                    subkey: subkey_path.to_string(),
                });
            }
        }
    }
    items
}

pub fn find_large_files() -> Vec<LargeFile> {
    let mut files = Vec::new();
    let root = Path::new(r"C:\");
    
    // Ignore common system/protected directories to speed up scan and avoid access denied loops
    let walker = WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let p = e.path();
            let p_str = p.to_string_lossy().to_lowercase();
            !p_str.starts_with(r"c:\windows") 
            && !p_str.starts_with(r"c:\program files")
            && !p_str.starts_with(r"c:\program files (x86)")
            && !p_str.starts_with(r"c:\programdata")
            && !p_str.starts_with(r"c:\$recycle.bin")
        });

    for entry in walker.filter_map(|e| e.ok()) {
        if let Ok(metadata) = entry.metadata() {
            if metadata.is_file() {
                let size = metadata.len();
                if size > 500 * 1024 * 1024 { // 500MB
                    files.push(LargeFile {
                        path: entry.path().to_path_buf(),
                        size,
                    });
                }
            }
        }
    }
    files
}

pub fn delete_junk_item(item: &JunkItem) -> Result<(), std::io::Error> {
    match &item.junk_type {
        JunkType::FileOrDir(path) => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            }
        },
        JunkType::RegistryValue { hkey, subkey, value_name } => {
            delete_registry_value(*hkey, subkey, value_name)
        }
    }
}

pub fn delete_registry_value(hkey_val: isize, subkey_path: &str, value_name: &str) -> Result<(), std::io::Error> {
    let hkey = RegKey::predef(hkey_val as *mut std::ffi::c_void);
    let subkey = hkey.open_subkey_with_flags(subkey_path, KEY_WRITE)?;
    subkey.delete_value(value_name)
}

pub fn run_disk_cleanup() {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cache_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches";
    
    if let Ok(caches) = hklm.open_subkey_with_flags(cache_path, KEY_READ | KEY_WRITE) {
        for key_name in caches.enum_keys().filter_map(|k| k.ok()) {
            if let Ok(subkey) = caches.open_subkey_with_flags(&key_name, KEY_WRITE) {
                let _ = subkey.set_value("StateFlags0001", &2u32);
            }
        }
    }

    let _ = Command::new("cleanmgr.exe").arg("/sagerun:1").creation_flags(CREATE_NO_WINDOW).status();
}

pub fn optimize_ram() {
    let _ = Command::new("ipconfig").arg("/flushdns").creation_flags(CREATE_NO_WINDOW).status();

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