//! Bethesda Softworks Archive file parser.

#![allow(non_snake_case)]

use chunk_parser::prelude::*;
pub use chunk_parser::Result;
use esm_bindings::bsa::*;

use std::ffi::CString;

//------------------------------------------------------------------------------
// https://en.uesp.net/wiki/Oblivion_Mod:Hash_Calculation

fn str_hash(str: &str) -> u32 {
    let mut hash: u32 = 0;
    for &char in str.as_bytes() {
        hash = hash.wrapping_mul(0x1003F);
        hash += char as u32;
    }
    hash
}

fn tes4_hash(name: &str, ext: &str) -> u64 {
    let mut hash: u64 = 0;

    if !name.is_empty() {
        let hash_bytes = [
            *name.as_bytes().last().unwrap_or(&0), // last char or 0
            *name.as_bytes().get(name.len() - 2).unwrap_or(&0), // second last char or 0
            name.len() as u8, // length
            *name.as_bytes().first().unwrap_or(&0), // first char or 0
        ];
        hash = u32::from_le_bytes(hash_bytes) as u64;

        if name.len() > 3 {
            hash += str_hash(&name[1..name.len()-2]) as u64 * 0x100000000;
        }
    }

    if !ext.is_empty() {
        hash += str_hash(ext) as u64 * 0x100000000;
    
        let mut i: u8 = 0;
        if ext == ".nif" { i = 1; }
        else if ext == ".kf" { i = 2; }
        else if ext == ".dds" { i = 3; }
        else if ext == ".wav" { i = 4; }
    
        if i != 0 {
            let a = ((i & 0xfc) << 5) + ((hash & 0xff000000) >> 24) as u8;
            let b = ((i & 0xfe) << 6) + (hash & 0x000000ff) as u8;
            let c = (i << 7) + ((hash & 0x0000ff00) >> 8) as u8;
    
            hash &= !0xFF00FFFF;
            hash += ((a as u32) << 24 | b as u32 | (c as u32) << 8) as u64;
        }
    }

    hash
}

//------------------------------------------------------------------------------

use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::str;

/// 64-bit BSA hasher.
#[derive(Default)]
pub struct BSAHasher { state: u64 }

// this implementation would ideally support &str but this feature is unstable
// instead a custom wrapper is used to call tes4_hash() on &str keys
impl std::hash::Hasher for BSAHasher {
    fn write(&mut self, _bytes: &[u8]) { unimplemented!("BSAHasher only supports u64 keys") }
    //fn write_str(&mut self, s: &str) { ... } // unstable
    fn write_u64(&mut self, i: u64) { self.state = i; } // only support u64
    fn finish(&self) -> u64 { self.state }
}

/// Specialised hash map for indexing TES4 hashes.
#[derive(Default)]
struct BSAHashMap<V>(HashMap<u64, V, BuildHasherDefault<BSAHasher>>);

impl<V> BSAHashMap<V> {
    /// Insert data directly into the u64 hash index.
    ///
    /// Archive file structures in Fallout 3 index files and folders directly by
    /// the u64 hash value of the original file path.
    pub fn insert(&mut self, k: u64, v: V) {
        self.0.insert(k, v);
    }

    /// Retrieve data indexed by string key.
    ///
    /// Data and scripts refer to archive files and folders by their original
    /// file path string.
    pub fn get(&self, k: &str) -> Option<&V> {
        self.0.get(&tes4_hash(k, ""))
    }
}

//------------------------------------------------------------------------------

/// BSA folder properties.
#[derive(Default)]
pub struct BSAFolder { pub count: u32, pub offset: u32 }

//------------------------------------------------------------------------------

/// Bethesda Softworks Archive parser.
#[chunk_parser(custom,depth)]
pub struct BSAParser {}

impl<R> BSAParser<R> where R: std::io::Read + std::io::Seek {
    /// Read a byte sized string.
    fn read_bzstring(&mut self) -> Result<CString> {
        let length = self.read::<u8>()? as usize;
        let mut v = Vec::with_capacity(length);
        unsafe {
            let ptr = v.as_mut_ptr();
            self.reader().read_exact(std::slice::from_raw_parts_mut(ptr, length))?;
            v.set_len(length-1);
        }
        Ok(unsafe { CString::from_vec_unchecked(v) })
    }

    /// Parser for version 104 of BSA used in Fallout 3.
    pub fn v104(&mut self) -> Result<()> {
        let header: BSAHeader = self.read()?;
        println!("{:?}", header);

        let mut folders = BSAHashMap::<BSAFolder>::default();

        for _ in 0..header.folder_count {
            let folder: BSAFolderRecord = self.read()?;
            let hash = folder.name_hash;
            folders.insert(hash, BSAFolder { count: folder.count, offset: folder.offset });
            println!("{:?} {:#018x}", folder, hash);
        }

        for _ in 0..header.folder_count {
            let name = self.read_bzstring()?;
            let folder = folders.get(name.to_str().unwrap()).unwrap();
            println!("{:?} {:#018x}", name, tes4_hash(name.to_str().unwrap(), ""));
            self.push();
            for _ in 0..folder.count {
                let file: BSAFileRecord = self.read()?;
                println!("  {:?}", file);
            }
            self.pop();
        }

        // now comes files...

        Ok(())
    }
}

//------------------------------------------------------------------------------

pub mod prelude {
    pub use chunk_parser::prelude::*;
    pub use super::BSAParser;
}

//==============================================================================

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn misc() -> chunk_parser::Result<()> {
        const DATA: &[u8] = include_bytes!("../data/Misc.bsa");
        let mut bsa = BSAParser::cursor(DATA);
        bsa.v104()
    }
}
