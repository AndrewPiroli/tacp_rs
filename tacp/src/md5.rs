//! Minimal RFC 1321 MD5 implementation for the TACACS+ obfuscation pad.

const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const CONSTANTS: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffered: usize,
    bytes: u64,
}

impl Md5 {
    pub const fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            buffer: [0; 64],
            buffered: 0,
            bytes: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.bytes = self.bytes.wrapping_add(data.len() as u64);

        if self.buffered != 0 {
            let count = data.len().min(64 - self.buffered);
            self.buffer[self.buffered..self.buffered + count].copy_from_slice(&data[..count]);
            self.buffered += count;
            data = &data[count..];
            if self.buffered < 64 {
                return;
            }
            Self::compress(&mut self.state, &self.buffer);
            self.buffered = 0;
        }

        while data.len() >= 64 {
            Self::compress(&mut self.state, &data[..64]);
            data = &data[64..];
        }
        self.buffer[..data.len()].copy_from_slice(data);
        self.buffered = data.len();
    }

    pub fn finalize_reset(&mut self) -> [u8; 16] {
        let bit_length = self.bytes.wrapping_mul(8).to_le_bytes();
        let padding_len = if self.buffered < 56 {
            56 - self.buffered
        } else {
            120 - self.buffered
        };
        let mut padding = [0; 64];
        padding[0] = 0x80;
        self.update(&padding[..padding_len]);
        self.update(&bit_length);

        let mut digest = [0; 16];
        for (index, word) in self.state.iter().enumerate() {
            digest[4 * index..4 * index + 4].copy_from_slice(&word.to_le_bytes());
        }
        *self = Self::new();
        digest
    }

    #[allow(clippy::many_single_char_names)]
    fn compress(state: &mut [u32; 4], block: &[u8]) {
        let mut words = [0; 16];
        for (index, word) in words.iter_mut().enumerate() {
            let offset = 4 * index;
            *word = u32::from_le_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }

        // RFC 1321 names the four working words a, b, c, d and the round values f, g.
        let [mut a, mut b, mut c, mut d] = *state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let next = a
                .wrapping_add(f)
                .wrapping_add(CONSTANTS[i])
                .wrapping_add(words[g])
                .rotate_left(SHIFTS[i]);
            (a, b, c, d) = (d, b.wrapping_add(next), b, c);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
}
