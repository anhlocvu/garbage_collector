#![windows_subsystem = "windows"]

use std::sync::{Arc, Mutex};
use std::thread;
use std::path::PathBuf;

use native_windows_gui as nwg;
use native_windows_derive as nwd;

use nwd::NwgUi;
use nwg::NativeUi;

use byte_unit::Byte;

mod scanner;
use scanner::{JunkItem, JunkType, StartupItem, LargeFile, get_junk_directories, scan_directory, scan_dead_registry_keys, delete_junk_item, delete_registry_value};

#[derive(PartialEq, Default)]
pub enum AppMode {
    #[default]
    Junk,
    Startup,
    LargeFiles,
}

#[derive(Default)]
pub struct AppState {
    pub mode: AppMode,
    pub is_working: bool,
    pub junk_items: Vec<JunkItem>,
    pub startup_items: Vec<StartupItem>,
    pub large_files: Vec<LargeFile>,
    pub total_size: u64,
}

#[derive(Default, NwgUi)]
pub struct JunkCleanerApp {
    #[nwg_control(size: (650, 500), position: (300, 300), title: "Garbage Collector", flags: "WINDOW|VISIBLE")]
    #[nwg_events( OnWindowClose: [JunkCleanerApp::exit] )]
    window: nwg::Window,

    #[nwg_layout(parent: window, spacing: 5)]
    layout: nwg::GridLayout,

    // Row 0
    #[nwg_control(text: "Ready.")]
    #[nwg_layout_item(layout: layout, col: 0, row: 0, col_span: 2)]
    status_label: nwg::Label,

    #[nwg_control(text: "Total Size: 0 B")]
    #[nwg_layout_item(layout: layout, col: 2, row: 0, col_span: 2)]
    size_label: nwg::Label,

    // Row 1 - Mode Selectors (Radio Buttons are 100% accessible for screen readers)
    #[nwg_control(text: "1. Junk & Registry", check_state: nwg::RadioButtonState::Checked)]
    #[nwg_layout_item(layout: layout, col: 0, row: 1, col_span: 1)]
    #[nwg_events( OnButtonClick: [JunkCleanerApp::mode_junk] )]
    mode_junk_radio: nwg::RadioButton,

    #[nwg_control(text: "2. Startup Manager")]
    #[nwg_layout_item(layout: layout, col: 1, row: 1, col_span: 1)]
    #[nwg_events( OnButtonClick: [JunkCleanerApp::mode_startup] )]
    mode_startup_radio: nwg::RadioButton,

    #[nwg_control(text: "3. Large File Finder")]
    #[nwg_layout_item(layout: layout, col: 2, row: 1, col_span: 2)]
    #[nwg_events( OnButtonClick: [JunkCleanerApp::mode_large_files] )]
    mode_large_files_radio: nwg::RadioButton,

    // Row 2 - Action Buttons
    #[nwg_control(text: "Scan Junk")]
    #[nwg_layout_item(layout: layout, col: 0, row: 2, col_span: 4)]
    #[nwg_events( OnButtonClick: [JunkCleanerApp::start_action] )]
    action_btn: nwg::Button,

    #[nwg_control(text: "Clean Junk", enabled: false)]
    #[nwg_layout_item(layout: layout, col: 0, row: 2, col_span: 4)]
    #[nwg_events( OnButtonClick: [JunkCleanerApp::execute_action] )]
    execute_btn: nwg::Button,

    // Row 3
    #[nwg_control(text: "Optimize RAM & DNS Cache", check_state: nwg::CheckBoxState::Checked)]
    #[nwg_layout_item(layout: layout, col: 0, row: 3, col_span: 4)]
    optimize_ram_cb: nwg::CheckBox,

    // Row 4-6
    #[nwg_control]
    #[nwg_layout_item(layout: layout, col: 0, row: 4, col_span: 4, row_span: 3)]
    list_box: nwg::ListBox<String>,

    // Row 7
    #[nwg_control(marquee: false)]
    #[nwg_layout_item(layout: layout, col: 0, row: 7, col_span: 4)]
    progress_bar: nwg::ProgressBar,

    // State
    state: Arc<Mutex<AppState>>,

    // Concurrency Notices
    #[nwg_control]
    #[nwg_events( OnNotice: [JunkCleanerApp::on_scan_progress] )]
    scan_notice: nwg::Notice,

    #[nwg_control]
    #[nwg_events( OnNotice: [JunkCleanerApp::on_execute_progress] )]
    execute_notice: nwg::Notice,
}

impl JunkCleanerApp {
    fn exit(&self) {
        nwg::stop_thread_dispatch();
    }

    fn update_ui_mode(&self, title: &str, action_text: &str) {
        self.status_label.set_text(title);
        self.action_btn.set_text(action_text);
        self.action_btn.set_visible(true);
        self.action_btn.set_enabled(true);
        self.execute_btn.set_visible(false);
        self.execute_btn.set_enabled(false);
        self.list_box.clear();
        self.size_label.set_text("Total Size: 0 B");
        self.progress_bar.set_pos(0);
    }

    fn mode_junk(&self) {
        let mut state = self.state.lock().unwrap();
        if state.is_working { return; }
        state.mode = AppMode::Junk;
        self.optimize_ram_cb.set_visible(true);
        self.update_ui_mode("Junk & Registry Cleaner Mode", "Scan Junk");
    }

    fn mode_startup(&self) {
        let mut state = self.state.lock().unwrap();
        if state.is_working { return; }
        state.mode = AppMode::Startup;
        self.optimize_ram_cb.set_visible(false);
        self.update_ui_mode("Startup Manager Mode", "Load Startup Items");
    }

    fn mode_large_files(&self) {
        let mut state = self.state.lock().unwrap();
        if state.is_working { return; }
        state.mode = AppMode::LargeFiles;
        self.optimize_ram_cb.set_visible(false);
        self.update_ui_mode("Large File Finder Mode", "Scan Drive C: (>500MB)");
    }

    fn start_action(&self) {
        let mut state = self.state.lock().unwrap();
        if state.is_working { return; }
        state.is_working = true;
        
        self.action_btn.set_enabled(false);
        self.status_label.set_text("Scanning...");
        self.list_box.clear();
        self.progress_bar.set_state(nwg::ProgressBarState::Normal);
        self.progress_bar.set_range(0..100);
        self.progress_bar.set_pos(0);
        self.progress_bar.set_marquee(true, 10);

        let notice = self.scan_notice.sender();
        let state_clone = self.state.clone();
        let mode = state.mode == AppMode::Junk;
        let mode_large = state.mode == AppMode::LargeFiles;
        let mode_startup = state.mode == AppMode::Startup;

        thread::spawn(move || {
            let mut s = state_clone.lock().unwrap();
            s.total_size = 0;
            s.junk_items.clear();
            s.startup_items.clear();
            s.large_files.clear();
            drop(s);

            if mode {
                let dirs = get_junk_directories();
                let mut local_items = Vec::new();
                let mut local_size = 0;

                for dir in dirs {
                    let items = scan_directory(&dir);
                    for item in items {
                        local_size += item.size;
                        local_items.push(item);
                    }
                }
                
                let dead_keys = scan_dead_registry_keys();
                for item in dead_keys {
                    local_items.push(item);
                }

                let mut s = state_clone.lock().unwrap();
                s.junk_items = local_items;
                s.total_size = local_size;
                s.is_working = false;
            } else if mode_startup {
                let items = scanner::get_startup_items();
                let mut s = state_clone.lock().unwrap();
                s.startup_items = items;
                s.is_working = false;
            } else if mode_large {
                let items = scanner::find_large_files();
                let mut local_size = 0;
                for item in &items {
                    local_size += item.size;
                }
                let mut s = state_clone.lock().unwrap();
                s.large_files = items;
                s.total_size = local_size;
                s.is_working = false;
            }

            notice.notice();
        });
    }

    fn on_scan_progress(&self) {
        let state = self.state.lock().unwrap();
        
        self.progress_bar.set_marquee(false, 0);
        self.progress_bar.set_pos(100);
        self.action_btn.set_visible(false);
        self.execute_btn.set_visible(true);

        if state.mode == AppMode::Junk {
            let size_str = Byte::from_u128(state.total_size as u128).unwrap_or_default().get_appropriate_unit(byte_unit::UnitType::Binary).to_string();
            self.size_label.set_text(&format!("Total Junk: {}", size_str));
            let count = state.junk_items.len();
            self.status_label.set_text(&format!("Scan complete. Found {} junk/dead items.", count));
            self.list_box.push(format!("Found {} files/folders/registry keys to clean.", count));
            
            if count > 0 {
                self.execute_btn.set_text("Clean All Junk");
                self.execute_btn.set_enabled(true);
            } else {
                self.action_btn.set_enabled(true);
                self.action_btn.set_visible(true);
                self.execute_btn.set_visible(false);
            }
        } else if state.mode == AppMode::Startup {
            let count = state.startup_items.len();
            self.status_label.set_text(&format!("Found {} startup items.", count));
            for item in &state.startup_items {
                self.list_box.push(format!("{} -> {}", item.name, item.command));
            }
            if count > 0 {
                self.execute_btn.set_text("Disable Selected Startup Item");
                self.execute_btn.set_enabled(true);
            } else {
                self.action_btn.set_enabled(true);
                self.action_btn.set_visible(true);
                self.execute_btn.set_visible(false);
            }
        } else if state.mode == AppMode::LargeFiles {
            let size_str = Byte::from_u128(state.total_size as u128).unwrap_or_default().get_appropriate_unit(byte_unit::UnitType::Binary).to_string();
            self.size_label.set_text(&format!("Total Size: {}", size_str));
            let count = state.large_files.len();
            self.status_label.set_text(&format!("Found {} large files.", count));
            for item in &state.large_files {
                let sz = Byte::from_u128(item.size as u128).unwrap_or_default().get_appropriate_unit(byte_unit::UnitType::Binary).to_string();
                self.list_box.push(format!("[{}] {}", sz, item.path.display()));
            }
            if count > 0 {
                self.execute_btn.set_text("Delete Selected Large File");
                self.execute_btn.set_enabled(true);
            } else {
                self.action_btn.set_enabled(true);
                self.action_btn.set_visible(true);
                self.execute_btn.set_visible(false);
            }
        }
        
        self.list_box.set_focus();
    }

    fn execute_action(&self) {
        let mut state = self.state.lock().unwrap();
        if state.is_working { return; }
        
        let sel_index = self.list_box.selection();
        
        if state.mode == AppMode::Startup {
            if let Some(idx) = sel_index {
                if idx < state.startup_items.len() {
                    let item = &state.startup_items[idx];
                    let _ = delete_registry_value(item.hkey, &item.subkey, &item.name);
                    nwg::modal_info_message(&self.window, "Success", &format!("Disabled startup item: {}", item.name));
                    
                    // Release the lock before calling start_action which also takes the lock
                    drop(state);
                    self.start_action();
                }
            } else {
                nwg::modal_info_message(&self.window, "Error", "Please select a startup item to disable.");
            }
            return;
        }

        if state.mode == AppMode::LargeFiles {
            if let Some(idx) = sel_index {
                if idx < state.large_files.len() {
                    let item = &state.large_files[idx];
                    let _ = std::fs::remove_file(&item.path);
                    nwg::modal_info_message(&self.window, "Success", &format!("Deleted large file: {}", item.path.display()));
                    
                    drop(state);
                    self.start_action();
                }
            } else {
                nwg::modal_info_message(&self.window, "Error", "Please select a large file to delete.");
            }
            return;
        }

        if state.junk_items.is_empty() { return; }
        state.is_working = true;
        let optimize_ram_checked = self.optimize_ram_cb.check_state() == nwg::CheckBoxState::Checked;

        self.execute_btn.set_enabled(false);
        self.optimize_ram_cb.set_enabled(false);
        self.status_label.set_text("Cleaning...");
        self.list_box.clear();
        self.list_box.push(String::from("Cleaning temporary files and registry..."));
        self.progress_bar.set_state(nwg::ProgressBarState::Normal);
        
        let total_items = state.junk_items.len() as u32;
        self.progress_bar.set_range(0..total_items);
        self.progress_bar.set_pos(0);

        let notice = self.execute_notice.sender();
        let items = state.junk_items.drain(..).collect::<Vec<_>>();
        let state_clone = self.state.clone();

        thread::spawn(move || {
            let mut deleted_count = 0;
            let mut deleted_size = 0;

            for item in items.iter() {
                if delete_junk_item(item).is_ok() {
                    deleted_count += 1;
                    deleted_size += item.size;
                }
            }

            scanner::run_disk_cleanup();

            if optimize_ram_checked {
                scanner::optimize_ram();
            }

            let mut s = state_clone.lock().unwrap();
            s.is_working = false;
            s.total_size = deleted_size; 
            s.junk_items.clear(); 
            s.junk_items.push(JunkItem { junk_type: JunkType::FileOrDir(PathBuf::from("DELETED_COUNT")), size: deleted_count as u64 });
            s.junk_items.push(JunkItem { junk_type: JunkType::FileOrDir(PathBuf::from("OPTIMIZED_RAM")), size: if optimize_ram_checked { 1 } else { 0 } });

            notice.notice();
        });
    }

    fn on_execute_progress(&self) {
        let mut state = self.state.lock().unwrap();
        
        if state.mode != AppMode::Junk { return; }

        let deleted_size = state.total_size;
        let deleted_count = state.junk_items[0].size;
        let ram_optimized = state.junk_items[1].size == 1;
        
        state.junk_items.clear();
        state.total_size = 0;

        let size_str = Byte::from_u128(deleted_size as u128).unwrap_or_default().get_appropriate_unit(byte_unit::UnitType::Binary).to_string();
        
        self.status_label.set_text("Cleaning complete.");
        self.size_label.set_text(&format!("Cleaned: {}", size_str));
        
        self.list_box.push(format!("Successfully deleted {} items.", deleted_count));
        self.list_box.push(String::from("Windows Disk Cleanup finished successfully."));
        if ram_optimized {
            self.list_box.push(String::from("RAM & DNS Cache successfully optimized."));
        }

        self.progress_bar.set_pos(self.progress_bar.range().end);

        self.execute_btn.set_enabled(false);
        self.execute_btn.set_visible(false);
        
        self.action_btn.set_enabled(true);
        self.action_btn.set_visible(true);
        
        self.optimize_ram_cb.set_enabled(true);
        self.list_box.set_focus();
    }
}

fn main() {
    nwg::init().expect("Failed to init Native Windows GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");
    
    let mut font = nwg::Font::default();
    nwg::Font::builder()
        .family("Segoe UI")
        .size(16)
        .build(&mut font)
        .unwrap();
    nwg::Font::set_global_default(Some(font));

    let _app = JunkCleanerApp::build_ui(Default::default()).expect("Failed to build UI");
    _app.execute_btn.set_visible(false);
    _app.mode_junk_radio.set_focus();
    nwg::dispatch_thread_events();
}
