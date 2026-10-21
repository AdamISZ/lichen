//! Writing state files so that a crash leaves the old file or the new
//! one, never a truncated one: the bytes to a temporary file beside it,
//! synced, then renamed over it, and the directory synced.

use std::io::Write as _;
use std::path::Path;

/// Replace `path` with `bytes`, atomically.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_with(path, bytes, None)
}

/// As [`write_atomic`], readable by its owner only (Unix): for files that
/// hold secrets.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_with(path, bytes, Some(0o600))
}

fn write_with(path: &Path, bytes: &[u8], mode: Option<u32>) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(m);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = o.open(&tmp)?;
    // a file made before with wider permissions keeps them through open
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(m))?;
    }
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    // the rename itself, durable (best effort where directories can't be
    // opened)
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_and_keeps_private_files_private() {
        let dir = std::env::temp_dir().join(format!("lichen-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("w.json");
        write_atomic(&p, b"one").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert!(!dir.join("w.json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
