// src/shard.rs

use reed_solomon_erasure::galois_8::{ReedSolomon, ShardByShard};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

pub const DATA_SHARDS: usize = 6;
pub const PARITY_SHARDS: usize = 3;
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

/// Split a file into shards and save them to disk.
/// Returns a Vec of shard file paths.
pub fn shard_file<P: AsRef<Path>>(filepath: P, out_dir: P) -> io::Result<Vec<String>> {
    let file_data = fs::read(&filepath)?;
    let file_len = file_data.len();

    // Pad to nearest multiple of DATA_SHARDS
    let mut padded = file_data.clone();
    let pad = (DATA_SHARDS - (file_len % DATA_SHARDS)) % DATA_SHARDS;
    padded.extend(vec![0u8; pad]);

    let shard_size = padded.len() / DATA_SHARDS;

    // Split into DATA_SHARDS chunks
    let mut shards: Vec<Vec<u8>> = padded
        .chunks(shard_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    // Add empty parity shards
    shards.extend((0..PARITY_SHARDS).map(|_| vec![0u8; shard_size]));

    // Create Reed-Solomon instance
    let r = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
    // ShardByShard does in-place parity
    let mut shard_refs: Vec<_> = shards.iter_mut().map(|x| &mut x[..]).collect();
    r.encode(&mut shard_refs).unwrap();

    // Save shards to disk
    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)?;
    let mut out_files = vec![];
    for (i, shard) in shards.iter().enumerate() {
        let out_path = out_dir.join(format!(
            "{}.shard{}.bin",
            Path::new(&filepath.as_ref()).file_name().unwrap().to_str().unwrap(),
            i
        ));
        let mut f = fs::File::create(&out_path)?;
        f.write_all(shard)?;
        out_files.push(out_path.to_string_lossy().to_string());
    }

    Ok(out_files)
}

/// Reconstruct a file from at least DATA_SHARDS available shards
pub fn recover_file<P: AsRef<Path>>(shard_files: &[P], out_file: P) -> io::Result<()> {
    if shard_files.len() < DATA_SHARDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Not enough shards to recover file!",
        ));
    }
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];

    // Read in available shards (by index from file name)
    for p in shard_files {
        let filename = p.as_ref().file_name().unwrap().to_str().unwrap();
        // Find shard index: "myfile.txt.shard2.bin"
        let idx = filename
            .rsplit(".shard")
            .next()
            .unwrap()
            .split('.')
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let data = fs::read(p)?;
        shards[idx] = Some(data);
    }

    // Collect mutable refs for reed-solomon
    let mut shard_refs: Vec<_> = shards
        .iter_mut()
        .map(|opt| opt.as_mut().map(|v| &mut v[..]))
        .collect();

    // Attempt to reconstruct missing shards
    let r = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS).unwrap();
    r.reconstruct(&mut shard_refs).unwrap();

    // Combine data shards to rebuild file
    let mut recovered: Vec<u8> = Vec::new();
    for i in 0..DATA_SHARDS {
        if let Some(ref s) = shard_refs[i] {
            recovered.extend_from_slice(s);
        }
    }

    let mut f = fs::File::create(out_file)?;
    f.write_all(&recovered)?;

    Ok(())
}
