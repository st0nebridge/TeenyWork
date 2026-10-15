//! Append-only JSON Lines ledgers for the Challenger's durable state.
//!
//! Purpose: write each record and its newline in one call, sync one record or a
//! group of records at once, rotate a ledger by size while keeping a fixed
//! number of older files, and replay a ledger by skipping malformed lines (a
//! torn final line after a crash, a corrupt line in the middle) with a warning
//! instead of refusing to start.
//! Depends on: `serde` / `serde_json` for encoding, `std::fs` for files.
//! Used by: the activity ledger (`activity.rs`, which writes groups and syncs
//! once per group) and the share ledger (`load_share_ledger` / `record_share`
//! in `main.rs`, one synced record at a time).

use serde::Serialize;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Default size cap for one ledger file: 16 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Rotated files kept beside the live file: `<path>.1` (newest) to `<path>.3`.
pub const ROTATED_FILES_KEPT: usize = 3;
/// Environment variable that overrides [`DEFAULT_MAX_BYTES`].
pub const MAX_BYTES_ENV: &str = "C2A_LEDGER_MAX_BYTES";
/// Malformed lines reported one by one per file before only the count is logged.
const WARNINGS_PER_FILE: u64 = 5;

/// The per-file size cap from `C2A_LEDGER_MAX_BYTES`, or the default when unset.
pub fn max_bytes_from_env() -> io::Result<u64> {
    match std::env::var_os(MAX_BYTES_ENV) {
        None => parse_max_bytes(None),
        Some(value) => match value.to_str() {
            Some(value) => parse_max_bytes(Some(value)),
            None => Err(invalid_max_bytes()),
        },
    }
}

/// Parses a size cap: `None` means the default; anything but a positive whole
/// number of bytes is refused so a typo cannot silently disable rotation.
pub fn parse_max_bytes(value: Option<&str>) -> io::Result<u64> {
    let Some(value) = value else {
        return Ok(DEFAULT_MAX_BYTES);
    };
    match value.trim().parse::<u64>() {
        Ok(bytes) if bytes > 0 => Ok(bytes),
        _ => Err(invalid_max_bytes()),
    }
}

fn invalid_max_bytes() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{MAX_BYTES_ENV} must be a positive whole number of bytes"),
    )
}

/// Encodes `record` as one JSON line, newline included.
pub fn encode_line<T: Serialize>(record: &T) -> io::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    Ok(line)
}

/// Writes an encoded line (record and newline together) in a single write, so a
/// crash cannot leave a complete record without its terminator.
fn write_line<W: Write>(writer: &mut W, line: &[u8]) -> io::Result<()> {
    writer.write_all(line)
}

/// `<path>.<index>`: the rotated file `index` generations older than the live one.
pub fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

/// The live file followed by its retained rotated files, newest first.
pub fn retained_paths(path: &Path) -> Vec<PathBuf> {
    std::iter::once(path.to_path_buf())
        .chain((1..=ROTATED_FILES_KEPT).map(|index| rotated_path(path, index)))
        .collect()
}

/// Passes each non-blank line of `path` (without its newline) to `on_line`, in
/// file order. A line `on_line` rejects is skipped, logged and counted, so a torn
/// final line or a corrupt middle line cannot stop startup. Returns the number
/// of lines skipped; a missing file replays as empty.
pub fn replay_file(
    path: &Path,
    mut on_line: impl FnMut(&[u8]) -> Result<(), String>,
) -> io::Result<u64> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut line_number = 0u64;
    let mut skipped = 0u64;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        line_number += 1;
        let terminated = line.last() == Some(&b'\n');
        let content = if terminated {
            &line[..line.len() - 1]
        } else {
            &line[..]
        };
        if content.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if let Err(error) = on_line(content) {
            skipped += 1;
            if skipped <= WARNINGS_PER_FILE {
                let kind = if terminated {
                    "malformed"
                } else {
                    "torn final"
                };
                eprintln!(
                    "warning: skipped {kind} line {line_number} in {}: {error}",
                    path.display()
                );
            }
        }
    }
    if skipped > WARNINGS_PER_FILE {
        eprintln!(
            "warning: skipped {skipped} malformed lines in {} in total",
            path.display()
        );
    }
    Ok(skipped)
}

/// The live, appendable file of one ledger. Each record is written in a single
/// write, and synced on its own ([`LedgerFile::append`]) or with the records
/// written before it ([`LedgerFile::write`], then [`LedgerFile::sync`]). Before
/// a record would take the file past its cap, the file is synced, rotated to
/// `<path>.1`, and a new live file is started.
pub struct LedgerFile {
    path: PathBuf,
    file: File,
    len: u64,
    holds_records: bool,
    needs_terminator: bool,
    unsynced: bool,
    max_bytes: u64,
    #[cfg(test)]
    syncs: u64,
}

impl LedgerFile {
    /// Opens (creating if needed) the live file. A final line left without its
    /// newline by a crash is terminated first, so the next record starts on a
    /// line of its own and replay skips only the fragment.
    pub fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        let mut file = open_for_append(path)?;
        let mut len = file.metadata()?.len();
        if len > 0 {
            let mut last_byte = [0u8; 1];
            file.seek(SeekFrom::End(-1))?;
            file.read_exact(&mut last_byte)?;
            if last_byte[0] != b'\n' {
                file.write_all(b"\n")?;
                file.sync_data()?;
                len += 1;
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            len,
            holds_records: len > 0,
            needs_terminator: false,
            unsynced: false,
            max_bytes,
            #[cfg(test)]
            syncs: 0,
        })
    }

    /// Appends `record` and syncs it (with anything written before it).
    pub fn append<T: Serialize>(
        &mut self,
        record: &T,
        header: impl FnOnce() -> io::Result<Option<Vec<u8>>>,
    ) -> io::Result<()> {
        self.write(record, header)?;
        self.sync()
    }

    /// Writes `record` without syncing it; the next [`LedgerFile::sync`] makes
    /// it durable together with every other record written since the last one.
    /// If it would take a file that already holds records past the cap, the
    /// file is rotated first and the new file begins with the line `header`
    /// returns, if any (the activity ledger's totals checkpoint).
    pub fn write<T: Serialize>(
        &mut self,
        record: &T,
        header: impl FnOnce() -> io::Result<Option<Vec<u8>>>,
    ) -> io::Result<()> {
        let line = encode_line(record)?;
        if self.holds_records && self.len + line.len() as u64 > self.max_bytes {
            let header = header()?;
            self.rotate(header.as_deref())?;
        }
        self.write_unsynced(&line)?;
        self.holds_records = true;
        Ok(())
    }

    /// Syncs every record written since the last sync; does nothing if there
    /// are none.
    pub fn sync(&mut self) -> io::Result<()> {
        if !self.unsynced {
            return Ok(());
        }
        self.file.sync_data()?;
        self.unsynced = false;
        #[cfg(test)]
        {
            self.syncs += 1;
        }
        Ok(())
    }

    /// Writes one complete line. After a failed write, the next line is
    /// prefixed with a newline so it cannot run into a partial one.
    fn write_unsynced(&mut self, line: &[u8]) -> io::Result<()> {
        let prefixed;
        let bytes = if self.needs_terminator {
            prefixed = [b"\n".as_slice(), line].concat();
            &prefixed[..]
        } else {
            line
        };
        let result = write_line(&mut self.file, bytes);
        self.unsynced = true;
        match result {
            Ok(()) => {
                self.len += bytes.len() as u64;
                self.needs_terminator = false;
                Ok(())
            }
            Err(error) => {
                self.len = self.file.metadata().map_or(self.len, |meta| meta.len());
                self.needs_terminator = true;
                Err(error)
            }
        }
    }

    /// Syncs the live file, shifts `<path>.N` to `<path>.N+1` (dropping the
    /// oldest), moves the live file to `<path>.1`, and starts a new live file
    /// with `header`. A crash at any step leaves every record in a file that
    /// replay still reads.
    fn rotate(&mut self, header: Option<&[u8]>) -> io::Result<()> {
        self.sync()?;
        remove_if_present(&rotated_path(&self.path, ROTATED_FILES_KEPT))?;
        for index in (1..ROTATED_FILES_KEPT).rev() {
            rename_if_present(
                &rotated_path(&self.path, index),
                &rotated_path(&self.path, index + 1),
            )?;
        }
        rename_if_present(&self.path, &rotated_path(&self.path, 1))?;
        self.file = open_for_append(&self.path)?;
        self.len = 0;
        self.holds_records = false;
        self.needs_terminator = false;
        if let Some(header) = header {
            self.write_unsynced(header)?;
        }
        Ok(())
    }
}

fn open_for_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn rename_if_present(from: &Path, to: &Path) -> io::Result<()> {
    match std::fs::rename(from, to) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ScratchDir;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Entry {
        n: u64,
        note: String,
    }

    /// Fixed-width records: every encoded line has the same length.
    fn entry(n: u64) -> Entry {
        Entry {
            n: 1000 + n,
            note: "x".to_string(),
        }
    }

    struct RecordingWriter {
        writes: Vec<Vec<u8>>,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn read_entries(path: &Path) -> (Vec<u64>, u64) {
        let mut numbers = Vec::new();
        let skipped = replay_file(path, |line| {
            let entry: Entry = serde_json::from_slice(line).map_err(|error| error.to_string())?;
            numbers.push(entry.n);
            Ok(())
        })
        .unwrap();
        (numbers, skipped)
    }

    #[test]
    fn record_and_newline_are_written_in_one_call() {
        let mut writer = RecordingWriter { writes: Vec::new() };
        write_line(&mut writer, &encode_line(&entry(7)).unwrap()).unwrap();
        assert_eq!(
            writer.writes,
            vec![b"{\"n\":1007,\"note\":\"x\"}\n".to_vec()],
            "the record and its newline must reach the file in a single write"
        );
    }

    #[test]
    fn replay_skips_a_garbage_middle_line_and_a_torn_final_line() {
        let dir = ScratchDir::new("ledger-replay");
        let path = dir.join("ledger.jsonl");
        std::fs::write(
            &path,
            b"{\"n\":1,\"note\":\"a\"}\nnot json \xff\xfe\n\n{\"n\":2,\"note\":\"b\"}\n{\"n\":3,\"no",
        )
        .unwrap();
        assert_eq!(read_entries(&path), (vec![1, 2], 2));
    }

    #[test]
    fn opening_terminates_a_torn_final_line_so_the_next_record_stands_alone() {
        let dir = ScratchDir::new("ledger-torn");
        let path = dir.join("ledger.jsonl");
        std::fs::write(&path, b"{\"n\":1,\"note\":\"a\"}\n{\"n\":2,\"no").unwrap();
        let mut ledger = LedgerFile::open(&path, DEFAULT_MAX_BYTES).unwrap();
        ledger.append(&entry(3), || Ok(None)).unwrap();
        drop(ledger);
        assert_eq!(read_entries(&path), (vec![1, 1003], 1));
    }

    #[test]
    fn rotation_happens_at_the_cap_and_keeps_a_fixed_number_of_files() {
        let dir = ScratchDir::new("ledger-rotation");
        let path = dir.join("ledger.jsonl");
        let line_length = encode_line(&entry(0)).unwrap().len() as u64;
        let cap = line_length * 3;
        let mut ledger = LedgerFile::open(&path, cap).unwrap();
        for n in 0..3 {
            ledger.append(&entry(n), || Ok(None)).unwrap();
        }
        assert!(
            !rotated_path(&path, 1).exists(),
            "a file exactly at the cap is kept"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), cap);

        let header = encode_line(&Entry {
            n: 9,
            note: "header".to_string(),
        })
        .unwrap();
        ledger.append(&entry(3), || Ok(Some(header))).unwrap();
        assert_eq!(
            read_entries(&rotated_path(&path, 1)).0,
            vec![1000, 1001, 1002]
        );
        assert_eq!(
            read_entries(&path).0,
            vec![9, 1003],
            "the next record over the cap opens a new file that starts with the header"
        );

        for n in 4..40 {
            ledger.append(&entry(n), || Ok(None)).unwrap();
        }
        drop(ledger);
        assert!(rotated_path(&path, ROTATED_FILES_KEPT).exists());
        assert!(!rotated_path(&path, ROTATED_FILES_KEPT + 1).exists());
        let mut retained = Vec::new();
        for file in retained_paths(&path).iter().rev() {
            assert!(
                std::fs::metadata(file).unwrap().len() <= cap,
                "{}",
                file.display()
            );
            retained.extend(read_entries(file).0);
        }
        let first = 1040 - retained.len() as u64;
        assert_eq!(
            retained,
            (first..1040).collect::<Vec<_>>(),
            "newest records, in order"
        );
    }

    #[test]
    fn records_written_together_are_synced_once() {
        let dir = ScratchDir::new("ledger-group");
        let path = dir.join("ledger.jsonl");
        let mut ledger = LedgerFile::open(&path, DEFAULT_MAX_BYTES).unwrap();
        for n in 0..5 {
            ledger.write(&entry(n), || Ok(None)).unwrap();
        }
        assert_eq!(ledger.syncs, 0, "writing alone does not sync");
        ledger.sync().unwrap();
        ledger.sync().unwrap();
        assert_eq!(
            ledger.syncs, 1,
            "one sync covers the five records; a second has nothing to sync"
        );
        ledger.append(&entry(5), || Ok(None)).unwrap();
        assert_eq!(ledger.syncs, 2, "append syncs its own record");
        drop(ledger);
        assert_eq!(read_entries(&path), ((1000..1006).collect(), 0));
    }

    #[test]
    fn rotation_syncs_the_outgoing_file_before_moving_it() {
        let dir = ScratchDir::new("ledger-rotation-sync");
        let path = dir.join("ledger.jsonl");
        let cap = encode_line(&entry(0)).unwrap().len() as u64 * 2;
        let mut ledger = LedgerFile::open(&path, cap).unwrap();
        for n in 0..3 {
            ledger.write(&entry(n), || Ok(None)).unwrap();
        }
        assert_eq!(
            ledger.syncs, 1,
            "the full file was synced before it became <path>.1"
        );
        ledger.sync().unwrap();
        assert_eq!(ledger.syncs, 2);
        drop(ledger);
        assert_eq!(read_entries(&rotated_path(&path, 1)).0, vec![1000, 1001]);
        assert_eq!(read_entries(&path).0, vec![1002]);
    }

    #[test]
    fn ledger_cap_defaults_to_16_mib_and_rejects_unusable_values() {
        assert_eq!(DEFAULT_MAX_BYTES, 16 * 1024 * 1024);
        assert_eq!(parse_max_bytes(None).unwrap(), DEFAULT_MAX_BYTES);
        assert_eq!(parse_max_bytes(Some("1048576")).unwrap(), 1_048_576);
        for unusable in ["", "0", "-5", "16MiB", "abc"] {
            assert!(parse_max_bytes(Some(unusable)).is_err(), "{unusable:?}");
        }
    }
}
