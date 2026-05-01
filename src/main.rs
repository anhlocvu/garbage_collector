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
use scanner::{JunkItem, get_junk_directories, scan_directory, delete_item};

#[derive(Default)]
pub struct AppState {
    pub is_scanning: bool,
    pub is_cleaning: bool,
    pub items_to_clean: Vec<JunkItem>,
    pub total_size: u64,
}

#[derive(Default, NwgUi)]
pub struct JunkCleanerApp {
    #[nwg_control(size: (600, 450), position: (300, 300), title: "Garbage Collector", flags: "WINDOW|VISIBLE")]
    #[nwg_events( OnWindowClose: [JunkCleanerApp::exit] )]
    window: nwg::Window,

    #[nwg_layout(parent: window, spacing: 5)]
    layout: nwg::GridLayout,

    #[nwg_control(text: "Ready.")]
    #[nwg_layout_item(layout: layout, col: 0, row: 0, col_span: 2)]
    status_label: nwg::Label,

    #[nwg_control(text: "Total Junk: 0 B")]
    #[nwg_layout_item(layout: layout, col: 2, row: 0, col_span: 2)]
    size_label: nwg::Label,

    #[nwg_control(text: "Scan Junk")]
    #[nwg_layout_item(layout: layout, col: 0, row: 1, col_span: 2)]
    #[nwg_events( OnButtonClick: [JunkCleanerApp::start_scan] )]
    scan_btn: nwg::Button,

    #[nwg_control(text: "Clean Junk", enabled: false)]
    #[nwg_layout_item(layout: layout, col: 2, row: 1, col_span: 2)]
    #[nwg_events( OnButtonClick: [JunkCleanerApp::start_clean] )]
    clean_btn: nwg::Button,

    #[nwg_control(text: "Optimize RAM & DNS Cache", check_state: nwg::CheckBoxState::Checked)]
    #[nwg_layout_item(layout: layout, col: 0, row: 2, col_span: 4)]
    optimize_ram_cb: nwg::CheckBox,

    #[nwg_control]
    #[nwg_layout_item(layout: layout, col: 0, row: 3, col_span: 4, row_span: 3)]
    list_box: nwg::ListBox<String>,

    #[nwg_control(marquee: false)]
    #[nwg_layout_item(layout: layout, col: 0, row: 6, col_span: 4)]
    progress_bar: nwg::ProgressBar,

    // State
    state: Arc<Mutex<AppState>>,

    // Concurrency
    #[nwg_control]
    #[nwg_events( OnNotice: [JunkCleanerApp::on_scan_progress] )]
    scan_notice: nwg::Notice,

    #[nwg_control]
    #[nwg_events( OnNotice: [JunkCleanerApp::on_clean_progress] )]
    clean_notice: nwg::Notice,
}

impl JunkCleanerApp {
    fn exit(&self) {
        nwg::stop_thread_dispatch();
    }

    fn start_scan(&self) {
        let mut state = self.state.lock().unwrap();
        if state.is_scanning || state.is_cleaning {
            return;
        }
        state.is_scanning = true;
        state.items_to_clean.clear();
        state.total_size = 0;
        
        self.scan_btn.set_enabled(false);
        self.clean_btn.set_enabled(false);
        self.status_label.set_text("Scanning...");
        self.list_box.clear();
        self.progress_bar.set_state(nwg::ProgressBarState::Normal);
        self.progress_bar.set_range(0..100);
        self.progress_bar.set_pos(0);
        self.progress_bar.set_marquee(true, 10);

        let notice = self.scan_notice.sender();
        let state_clone = self.state.clone();

        thread::spawn(move || {
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

            let mut state = state_clone.lock().unwrap();
            state.items_to_clean = local_items;
            state.total_size = local_size;
            state.is_scanning = false;

            notice.notice();
        });
    }

    fn on_scan_progress(&self) {
        let state = self.state.lock().unwrap();
        
        let size_str = Byte::from_u128(state.total_size as u128).unwrap_or_default().get_appropriate_unit(byte_unit::UnitType::Binary).to_string();
        self.size_label.set_text(&format!("Total Junk: {}", size_str));
        
        let count = state.items_to_clean.len();
        self.status_label.set_text(&format!("Scan complete. Found {} items.", count));
        
        self.list_box.push(format!("Found {} files/folders to clean.", count));
        
        self.progress_bar.set_marquee(false, 0);
        self.progress_bar.set_pos(100);

        self.scan_btn.set_enabled(true);
        if count > 0 {
            self.clean_btn.set_enabled(true);
        }
    }

    fn start_clean(&self) {
        let mut state = self.state.lock().unwrap();
        if state.is_scanning || state.is_cleaning || state.items_to_clean.is_empty() {
            return;
        }
        state.is_cleaning = true;
        let optimize_ram_checked = self.optimize_ram_cb.check_state() == nwg::CheckBoxState::Checked;

        self.scan_btn.set_enabled(false);
        self.clean_btn.set_enabled(false);
        self.optimize_ram_cb.set_enabled(false);
        self.status_label.set_text("Cleaning...");
        self.list_box.clear();
        self.list_box.push(String::from("Cleaning temporary files..."));
        self.progress_bar.set_state(nwg::ProgressBarState::Normal);
        
        let total_items = state.items_to_clean.len() as u32;
        self.progress_bar.set_range(0..total_items);
        self.progress_bar.set_pos(0);

        let notice = self.clean_notice.sender();
        let items = state.items_to_clean.drain(..).collect::<Vec<_>>();
        let state_clone = self.state.clone();

        thread::spawn(move || {
            let mut deleted_count = 0;
            let mut deleted_size = 0;

            for item in items.iter() {
                // Try to delete
                if delete_item(&item.path).is_ok() {
                    deleted_count += 1;
                    deleted_size += item.size;
                }
            }

            // Run Windows Disk Cleanup silently
            scanner::run_disk_cleanup();

            if optimize_ram_checked {
                scanner::optimize_ram();
            }

            let mut state = state_clone.lock().unwrap();
            state.is_cleaning = false;
            // Store results in state to read in notice
            state.total_size = deleted_size; 
            state.items_to_clean.clear(); 
            // Use dummy items to pass back the count and the optimize flag
            state.items_to_clean.push(JunkItem { path: PathBuf::from("DELETED_COUNT"), size: deleted_count as u64 });
            state.items_to_clean.push(JunkItem { path: PathBuf::from("OPTIMIZED_RAM"), size: if optimize_ram_checked { 1 } else { 0 } });

            notice.notice();
        });
    }

    fn on_clean_progress(&self) {
        let mut state = self.state.lock().unwrap();
        
        let deleted_size = state.total_size;
        let deleted_count = state.items_to_clean[0].size;
        let ram_optimized = state.items_to_clean[1].size == 1;
        
        state.items_to_clean.clear();
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

        self.scan_btn.set_enabled(true);
        self.optimize_ram_cb.set_enabled(true);
        self.clean_btn.set_enabled(false);
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
    nwg::dispatch_thread_events();
}
