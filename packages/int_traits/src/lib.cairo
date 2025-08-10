pub trait U32FromBeBytes {
    fn from_be_bytes(bytes: [u8; 4]) -> u32;
}

pub trait U64FromBeBytes {
    fn from_be_bytes(bytes: [u8; 8]) -> u64;
}

pub trait U16FromLeBytes {
    fn from_le_bytes(bytes: [u8; 2]) -> u16;
}

pub trait U32FromLeBytes {
    fn from_le_bytes(bytes: [u8; 4]) -> u32;
}

pub trait U64FromLeBytes {
    fn from_le_bytes(bytes: [u8; 8]) -> u64;
}

pub trait U16ToLeBytes {
    fn to_le_bytes(self: u16) -> [u8; 2];
}

pub trait U32ToLeBytes {
    fn to_le_bytes(self: u32) -> [u8; 4];
}

pub trait U64ToLeBytes {
    fn to_le_bytes(self: u64) -> [u8; 8];
}

pub trait U64FromBytesBe {
    fn from_be_byte_span(bytes: @Span<u8>) -> u64;
}

pub trait U256FromBytesBe {
    fn from_be_byte_span(bytes: @Span<u8>) -> u256;
}

pub impl U32FromBeBytesImpl of U32FromBeBytes {
    fn from_be_bytes(bytes: [u8; 4]) -> u32 {
        let [b0, b1, b2, b3] = bytes;

        Into::<_, u32>::into(b0) * 0b1_00000000_00000000_00000000_u32
            + Into::<_, u32>::into(b1) * 0b1_00000000_00000000_u32
            + Into::<_, u32>::into(b2) * 0b1_00000000_u32
            + Into::<_, u32>::into(b3)
    }
}

pub impl U64FromBeBytesImpl of U64FromBeBytes {
    fn from_be_bytes(bytes: [u8; 8]) -> u64 {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = bytes;

        Into::<_, u64>::into(b0)
            * 0b1_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b1)
                * 0b1_00000000_00000000_00000000_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b2) * 0b1_00000000_00000000_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b3) * 0b1_00000000_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b4) * 0b1_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b5) * 0b1_00000000_00000000_u64
            + Into::<_, u64>::into(b6) * 0b1_00000000_u64
            + Into::<_, u64>::into(b7)
    }
}

impl U16FromLeBytesImpl of U16FromLeBytes {
    fn from_le_bytes(bytes: [u8; 2]) -> u16 {
        let [b0, b1] = bytes;

        Into::<_, u16>::into(b0) + Into::<_, u16>::into(b1) * 0b1_00000000_u16
    }
}

impl U32FromLeBytesImpl of U32FromLeBytes {
    fn from_le_bytes(bytes: [u8; 4]) -> u32 {
        let [b0, b1, b2, b3] = bytes;

        Into::<_, u32>::into(b0)
            + Into::<_, u32>::into(b1) * 0b1_00000000_u32
            + Into::<_, u32>::into(b2) * 0b1_00000000_00000000_u32
            + Into::<_, u32>::into(b3) * 0b1_00000000_00000000_00000000_u32
    }
}

impl U64FromLeBytesImpl of U64FromLeBytes {
    fn from_le_bytes(bytes: [u8; 8]) -> u64 {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = bytes;

        Into::<_, u64>::into(b0)
            + Into::<_, u64>::into(b1) * 0b1_00000000_u64
            + Into::<_, u64>::into(b2) * 0b1_00000000_00000000_u64
            + Into::<_, u64>::into(b3) * 0b1_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b4) * 0b1_00000000_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b5) * 0b1_00000000_00000000_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b6)
                * 0b1_00000000_00000000_00000000_00000000_00000000_00000000_u64
            + Into::<_, u64>::into(b7)
                * 0b1_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64
    }
}

impl U16ToLeBytesImpl of U16ToLeBytes {
    fn to_le_bytes(self: u16) -> [u8; 2] {
        let b0: u8 = (self & 0xff).try_into().unwrap();
        let b1: u8 = ((self / 0b1_00000000) & 0xff).try_into().unwrap();

        [b0, b1]
    }
}

pub impl U256FromBytesBeImpl of U256FromBytesBe {
    /// Creates and initializes a [`u256`].
    ///
    /// The bytes are in big-endian byte order.
    fn from_be_byte_span(bytes: @Span<u8>) -> u256 {
        if bytes.is_empty() {
            0
        } else {
            // CAIRO: We're using `u256` in place of `BigUint`. Unlike `BigUint`, `u256` has a
            //        limited range and here we just panic.
            assert!(bytes.len() <= 32, "u256: byte slice too large");

            let mut result = 0;
            let mut iter = bytes.clone();
            while let Some(byte) = iter.pop_front() {
                result = result * 256 + Into::<_, u256>::into(*byte);
            }

            result
        }
    }
}

impl U32ToLeBytesImpl of U32ToLeBytes {
    fn to_le_bytes(self: u32) -> [u8; 4] {
        let b0: u8 = (self & 0xff).try_into().unwrap();
        let b1: u8 = ((self / 0b1_00000000) & 0xff).try_into().unwrap();
        let b2: u8 = ((self / 0b1_00000000_00000000) & 0xff).try_into().unwrap();
        let b3: u8 = ((self / 0b1_00000000_00000000_00000000) & 0xff).try_into().unwrap();

        [b0, b1, b2, b3]
    }
}

impl U64ToLeBytesImpl of U64ToLeBytes {
    fn to_le_bytes(self: u64) -> [u8; 8] {
        let b0: u8 = (self & 0xff).try_into().unwrap();
        let b1: u8 = ((self / 0b1_00000000) & 0xff).try_into().unwrap();
        let b2: u8 = ((self / 0b1_00000000_00000000) & 0xff).try_into().unwrap();
        let b3: u8 = ((self / 0b1_00000000_00000000_00000000) & 0xff).try_into().unwrap();
        let b4: u8 = ((self / 0b1_00000000_00000000_00000000_00000000) & 0xff).try_into().unwrap();
        let b5: u8 = ((self / 0b1_00000000_00000000_00000000_00000000_00000000) & 0xff)
            .try_into()
            .unwrap();
        let b6: u8 = ((self / 0b1_00000000_00000000_00000000_00000000_00000000_00000000) & 0xff)
            .try_into()
            .unwrap();
        let b7: u8 = ((self / 0b1_00000000_00000000_00000000_00000000_00000000_00000000_00000000)
            & 0xff)
            .try_into()
            .unwrap();

        [b0, b1, b2, b3, b4, b5, b6, b7]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
