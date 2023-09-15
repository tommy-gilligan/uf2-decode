//! # UF2
//!
//! Basic decoding of UF2.  This is a partial
//! adaptation of
//! [`uf2conv.py`](https://github.com/microsoft/uf2/blob/17e70bf908e6abdf4f4acc50a9c84e5709ded2a9/utils/uf2conv.py).

use std::collections::HashMap;

#[derive(Debug)]
pub enum Error {
    TooMuchPaddingRequired(usize),
    NonWordPaddingSize(usize),
    InvalidDataSize(usize),
}

/// Takes a UF2 and returns raw bin coupled with family ID-target address pairs
///
/// # Errors
///
/// - [`Error::TooMuchPaddingRequired`]
/// - [`Error::NonWordPaddingSize`]
/// - [`Error::InvalidDataSize`]
pub fn convert_from_uf2(buf: &[u8]) -> Result<(Vec<u8>, HashMap<u32, usize>), Error> {
    let mut curr_addr: Option<usize> = None;
    let mut curr_family_id: Option<u32> = None;
    let mut families_found: HashMap<u32, usize> = HashMap::new();
    let mut outp: Vec<u8> = Vec::new();
    for (index, block) in buf.chunks_exact(512).enumerate() {
        let hd: [u32; 8] = block[0..32]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();
        // Skipping block at with bad magic or NO-flash flag set; skip block
        if (hd[0], hd[1]) != (0x0A32_4655, 0x9E5D_5157) || (hd[2] & 1) != 0 {
            continue;
        }
        let data_len = hd[4] as usize;
        if data_len > 476 {
            return Err(Error::InvalidDataSize(index));
        }
        let new_addr = hd[3] as usize;
        if (hd[2] & 0x2000) != 0 && curr_family_id.is_none() {
            curr_family_id = Some(hd[7]);
        }

        if curr_addr.is_none() || ((hd[2] & 0x2000) != 0 && Some(hd[7]) != curr_family_id) {
            curr_family_id = Some(hd[7]);
            curr_addr = Some(new_addr);
        }
        let mut padding = new_addr - curr_addr.unwrap();
        if padding > 10 * 1024 * 1024 {
            return Err(Error::TooMuchPaddingRequired(index));
        }
        if padding % 4 != 0 {
            return Err(Error::NonWordPaddingSize(index));
        }
        while padding > 0 {
            padding -= 4;
            outp.extend_from_slice(&[0x0, 0x0, 0x0, 0x0]);
        }

        if (hd[2] & 0x2000) != 0 {
            outp.extend_from_slice(&block[32..(32 + data_len)]);
        }
        curr_addr = Some(new_addr + data_len);
        if (hd[2] & 0x2000) != 0 {
            match families_found.get(&hd[7]) {
                Some(v) if *v > new_addr => {
                    families_found.insert(hd[7], new_addr);
                }
                None => {
                    families_found.insert(hd[7], new_addr);
                }
                _ => (),
            }
        }
    }

    Ok((outp, families_found))
}
