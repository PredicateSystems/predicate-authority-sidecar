//! Export logs and paths into a small zip for support.

use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

pub fn write_diagnostics_zip<W: Write + std::io::Seek>(
    writer: W,
    logs: &str,
    meta: &str,
) -> Result<(), String> {
    let mut zip = ZipWriter::new(writer);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("README.txt", opts)
        .map_err(|e| e.to_string())?;
    zip.write_all(
        b"Predicate Authority Desktop - diagnostics bundle\n\
          Contains process logs (if captured) and local path metadata.\n\
          Review before sharing; may contain hostnames or file paths.\n",
    )
    .map_err(|e| e.to_string())?;
    zip.start_file("process_logs.txt", opts)
        .map_err(|e| e.to_string())?;
    zip.write_all(logs.as_bytes()).map_err(|e| e.to_string())?;
    zip.start_file("paths_and_settings.txt", opts)
        .map_err(|e| e.to_string())?;
    zip.write_all(meta.as_bytes()).map_err(|e| e.to_string())?;
    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}
