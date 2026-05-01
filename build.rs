fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        // This ensures the application requests UAC elevation (Administrator privileges)
        res.set_manifest_file("app.manifest");
        res.compile().unwrap();
    }
}
