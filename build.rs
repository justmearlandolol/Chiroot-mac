fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new().commands(&[
                "get_app_entry_url",
                "open_external_url",
                "pick_import_files",
                "read_imported_file_chunk",
                "release_imported_file",
                "list_macos_audio_devices",
                "start_google_auth",
                "complete_oauth_from_url",
                "get_auth_session",
                "logout_auth",
                "sync_web_session",
            ]),
        ),
    )
    .expect("failed to run tauri-build");
}
