use anyhow::Result;
use dracon_security::WardenSecurity;
use std::fs;

#[test]
fn test_restore_workflow() -> Result<()> {
    // 1. Setup Security
    let mut security = WardenSecurity::new(None)?;
    let key = age::x25519::Identity::generate();
    security.add_memory_identity(key);

    // 2. Create a dummy file in a temp dir
    let temp_dir = tempfile::tempdir()?;
    let file_path = temp_dir.path().join("config_restore.env");
    let original_content = b"SECRET=super_secret_restore_value";
    fs::write(&file_path, original_content)?;

    // 3. Backup the file
    // Note: This writes to real ~/.dracon/backups
    let result = security.backup_file(&file_path, original_content);
    assert!(result.is_ok(), "Backup failed: {:?}", result.err());
    let backup_path = result.unwrap();

    // 4. "Corrupt" the original file
    fs::write(&file_path, b"SECRET=corrupted_data")?;

    // 5. Restore it
    let restored_path = security.restore_file(&file_path)?;

    // 6. Verify content matches original
    let restored_content = fs::read(&file_path)?;
    assert_eq!(restored_content, original_content);
    assert_eq!(restored_path, backup_path);

    // Cleanup: Try to delete the backup file
    let _ = fs::remove_file(backup_path);

    Ok(())
}
