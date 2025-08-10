use time::{OffsetDateTime, OffsetDateTimeTrait, TimeTrait};
use crate::types::enclave_identity::{EnclaveIdentityV2Inner, EnclaveIdentityV2TcbLevelItem};
use crate::types::tcbinfo::{
    TcbComponent, TcbInfoV3Inner, TcbInfoV3TcbLevel, TcbInfoV3TcbLevelItem, TdxModule,
    TdxModuleIdentities, TdxModuleIdentitiesTcbLevelItem,
};

/// A simple trait for serializing a value into JSON string.
///
/// This trait does not handle errors. Implementations must panic on errors instead.
pub trait JsonSerialize<T> {
    fn serialize(value: @T, ref output: ByteArray);
}

impl StringSpanJsonSerialize of JsonSerialize<Span<ByteArray>> {
    fn serialize(value: @Span<ByteArray>, ref output: ByteArray) {
        output.append(@"[");

        let mut iter = value.clone();
        let mut first = true;
        while let Option::Some(item) = iter.pop_front() {
            if !first {
                output.append(@",");
            }
            first = false;

            append_json_string(item, ref output);
        }

        output.append(@"]");
    }
}

impl EnclaveIdentityV2TcbLevelItemJson of JsonSerialize<EnclaveIdentityV2TcbLevelItem> {
    fn serialize(value: @EnclaveIdentityV2TcbLevelItem, ref output: ByteArray) {
        output.append(@"{");

        // tcb object
        append_json_field_name(@"tcb", ref output);
        output.append(@"{");
        append_json_field_name(@"isvsvn", ref output);
        append_json_number(value.tcb.isvsvn, ref output);
        output.append(@"}");

        // tcbDate
        output.append(@",");
        append_json_field_name(@"tcbDate", ref output);
        let tcb_date_str = format_iso8601_utc(value.tcb_date);
        append_json_string(@tcb_date_str, ref output);

        // tcbStatus
        output.append(@",");
        append_json_field_name(@"tcbStatus", ref output);
        append_json_string(value.tcb_status, ref output);

        // advisoryIDs (optional)
        match value.advisory_ids {
            Option::Some(ids) => {
                output.append(@",");
                append_json_field_name(@"advisoryIDs", ref output);
                JsonSerialize::<Span<ByteArray>>::serialize(ids, ref output);
            },
            Option::None => { // Omit field when None
            },
        }

        output.append(@"}");
    }
}

impl TcbLevelItemSpanJsonSerialize of JsonSerialize<Span<EnclaveIdentityV2TcbLevelItem>> {
    fn serialize(value: @Span<EnclaveIdentityV2TcbLevelItem>, ref output: ByteArray) {
        output.append(@"[");

        let mut iter = value.clone();
        let mut first = true;
        while let Option::Some(level) = iter.pop_front() {
            if !first {
                output.append(@",");
            }
            first = false;

            JsonSerialize::<EnclaveIdentityV2TcbLevelItem>::serialize(level, ref output);
        }

        output.append(@"]");
    }
}

pub impl EnclaveIdentityV2InnerJson of JsonSerialize<EnclaveIdentityV2Inner> {
    fn serialize(value: @EnclaveIdentityV2Inner, ref output: ByteArray) {
        output.append(@"{");

        // id
        append_json_field_name(@"id", ref output);
        append_json_string(value.id, ref output);

        // version
        output.append(@",");
        append_json_field_name(@"version", ref output);
        append_json_number(value.version, ref output);

        // issueDate
        output.append(@",");
        append_json_field_name(@"issueDate", ref output);
        let issue_date_str = format_iso8601_utc(value.issue_date);
        append_json_string(@issue_date_str, ref output);

        // nextUpdate
        output.append(@",");
        append_json_field_name(@"nextUpdate", ref output);
        let next_update_str = format_iso8601_utc(value.next_update);
        append_json_string(@next_update_str, ref output);

        // tcbEvaluationDataNumber
        output.append(@",");
        append_json_field_name(@"tcbEvaluationDataNumber", ref output);
        append_json_number(value.tcb_evaluation_data_number, ref output);

        // miscselect
        output.append(@",");
        append_json_field_name(@"miscselect", ref output);
        append_json_hex_bytes(value.miscselect, ref output);

        // miscselectMask
        output.append(@",");
        append_json_field_name(@"miscselectMask", ref output);
        append_json_hex_bytes(value.miscselect_mask, ref output);

        // attributes
        output.append(@",");
        append_json_field_name(@"attributes", ref output);
        append_json_hex_bytes(value.attributes, ref output);

        // attributesMask
        output.append(@",");
        append_json_field_name(@"attributesMask", ref output);
        append_json_hex_bytes(value.attributes_mask, ref output);

        // mrsigner
        output.append(@",");
        append_json_field_name(@"mrsigner", ref output);
        append_json_hex_bytes(value.mrsigner, ref output);

        // isvprodid
        output.append(@",");
        append_json_field_name(@"isvprodid", ref output);
        append_json_number(value.isvprodid, ref output);

        // tcbLevels (array)
        output.append(@",");
        append_json_field_name(@"tcbLevels", ref output);
        JsonSerialize::<
            Span<EnclaveIdentityV2TcbLevelItem>,
        >::serialize(value.tcb_levels, ref output);

        output.append(@"}");
    }
}

pub impl TcbInfoV3InnerJson of JsonSerialize<TcbInfoV3Inner> {
    fn serialize(value: @TcbInfoV3Inner, ref output: ByteArray) {
        output.append(@"{");

        // id
        append_json_field_name(@"id", ref output);
        append_json_string(value.id, ref output);

        // version
        output.append(@",");
        append_json_field_name(@"version", ref output);
        append_json_number(value.version, ref output);

        // issueDate
        output.append(@",");
        append_json_field_name(@"issueDate", ref output);
        let issue_date_str = format_iso8601_utc(value.issue_date);
        append_json_string(@issue_date_str, ref output);

        // nextUpdate
        output.append(@",");
        append_json_field_name(@"nextUpdate", ref output);
        let next_update_str = format_iso8601_utc(value.next_update);
        append_json_string(@next_update_str, ref output);

        // fmspc
        output.append(@",");
        append_json_field_name(@"fmspc", ref output);
        append_json_hex_bytes_lowercase(value.fmspc, ref output);

        // pceId
        output.append(@",");
        append_json_field_name(@"pceId", ref output);
        append_json_hex_bytes_lowercase(value.pce_id, ref output);

        // tcbType
        output.append(@",");
        append_json_field_name(@"tcbType", ref output);
        append_json_number(value.tcb_type, ref output);

        // tcbEvaluationDataNumber
        output.append(@",");
        append_json_field_name(@"tcbEvaluationDataNumber", ref output);
        append_json_number(value.tcb_evaluation_data_number, ref output);

        // tdxModule (optional)
        match value.tdx_module {
            Option::Some(tdx_module) => {
                output.append(@",");
                append_json_field_name(@"tdxModule", ref output);
                JsonSerialize::<TdxModule>::serialize(tdx_module, ref output);
            },
            Option::None => {},
        }

        // tdxModuleIdentities (optional)
        match value.tdx_module_identities {
            Option::Some(tdx_module_identities) => {
                output.append(@",");
                append_json_field_name(@"tdxModuleIdentities", ref output);
                JsonSerialize::<
                    Array<TdxModuleIdentities>,
                >::serialize(tdx_module_identities, ref output);
            },
            Option::None => {},
        }

        // tcbLevels (array)
        output.append(@",");
        append_json_field_name(@"tcbLevels", ref output);
        JsonSerialize::<Array<TcbInfoV3TcbLevelItem>>::serialize(value.tcb_levels, ref output);

        output.append(@"}");
    }
}

pub impl TdxModuleJson of JsonSerialize<TdxModule> {
    fn serialize(value: @TdxModule, ref output: ByteArray) {
        output.append(@"{");

        // mrsigner
        append_json_field_name(@"mrsigner", ref output);
        append_json_hex_bytes(value.mrsigner, ref output);

        // attributes
        output.append(@",");
        append_json_field_name(@"attributes", ref output);
        append_json_hex_bytes(value.attributes, ref output);

        // attributesMask
        output.append(@",");
        append_json_field_name(@"attributesMask", ref output);
        append_json_hex_bytes(value.attributes_mask, ref output);

        output.append(@"}");
    }
}

pub impl TdxModuleIdentitiesJson of JsonSerialize<TdxModuleIdentities> {
    fn serialize(value: @TdxModuleIdentities, ref output: ByteArray) {
        output.append(@"{");

        // id
        append_json_field_name(@"id", ref output);
        append_json_string(value.id, ref output);

        // mrsigner
        output.append(@",");
        append_json_field_name(@"mrsigner", ref output);
        append_json_hex_bytes(value.mrsigner, ref output);

        // attributes
        output.append(@",");
        append_json_field_name(@"attributes", ref output);
        append_json_hex_bytes(value.attributes, ref output);

        // attributesMask
        output.append(@",");
        append_json_field_name(@"attributesMask", ref output);
        append_json_hex_bytes(value.attributes_mask, ref output);

        // tcbLevels
        output.append(@",");
        append_json_field_name(@"tcbLevels", ref output);
        JsonSerialize::<
            Array<TdxModuleIdentitiesTcbLevelItem>,
        >::serialize(value.tcb_levels, ref output);

        output.append(@"}");
    }
}

pub impl TdxModuleIdentitiesTcbLevelItemJson of JsonSerialize<TdxModuleIdentitiesTcbLevelItem> {
    fn serialize(value: @TdxModuleIdentitiesTcbLevelItem, ref output: ByteArray) {
        output.append(@"{");

        // tcb
        append_json_field_name(@"tcb", ref output);
        output.append(@"{");
        append_json_field_name(@"isvsvn", ref output);
        append_json_number(value.tcb.isvsvn, ref output);
        output.append(@"}");

        // tcbDate
        output.append(@",");
        append_json_field_name(@"tcbDate", ref output);
        let tcb_date_str = format_iso8601_utc(value.tcb_date);
        append_json_string(@tcb_date_str, ref output);

        // tcbStatus
        output.append(@",");
        append_json_field_name(@"tcbStatus", ref output);
        append_json_string(value.tcb_status, ref output);

        // advisoryIDs (optional)
        match value.advisory_ids {
            Option::Some(advisory_ids) => {
                output.append(@",");
                append_json_field_name(@"advisoryIDs", ref output);
                JsonSerialize::<Span<ByteArray>>::serialize(advisory_ids, ref output);
            },
            Option::None => {},
        }

        output.append(@"}");
    }
}

pub impl TcbInfoV3TcbLevelItemJson of JsonSerialize<TcbInfoV3TcbLevelItem> {
    fn serialize(value: @TcbInfoV3TcbLevelItem, ref output: ByteArray) {
        output.append(@"{");

        // tcb
        append_json_field_name(@"tcb", ref output);
        JsonSerialize::<TcbInfoV3TcbLevel>::serialize(value.tcb, ref output);

        // tcbDate
        output.append(@",");
        append_json_field_name(@"tcbDate", ref output);
        let tcb_date_str = format_iso8601_utc(value.tcb_date);
        append_json_string(@tcb_date_str, ref output);

        // tcbStatus
        output.append(@",");
        append_json_field_name(@"tcbStatus", ref output);
        append_json_string(value.tcb_status, ref output);

        // advisoryIDs (optional)
        match value.advisory_ids {
            Option::Some(advisory_ids) => {
                output.append(@",");
                append_json_field_name(@"advisoryIDs", ref output);
                JsonSerialize::<Span<ByteArray>>::serialize(advisory_ids, ref output);
            },
            Option::None => {},
        }

        output.append(@"}");
    }
}

pub impl TcbInfoV3TcbLevelJson of JsonSerialize<TcbInfoV3TcbLevel> {
    fn serialize(value: @TcbInfoV3TcbLevel, ref output: ByteArray) {
        output.append(@"{");

        // sgxtcbcomponents
        append_json_field_name(@"sgxtcbcomponents", ref output);
        JsonSerialize::<Array<TcbComponent>>::serialize(value.sgxtcbcomponents, ref output);

        // pcesvn
        output.append(@",");
        append_json_field_name(@"pcesvn", ref output);
        append_json_number(value.pcesvn, ref output);

        // tdxtcbcomponents (optional)
        match value.tdxtcbcomponents {
            Option::Some(tdxtcbcomponents) => {
                output.append(@",");
                append_json_field_name(@"tdxtcbcomponents", ref output);
                JsonSerialize::<Array<TcbComponent>>::serialize(tdxtcbcomponents, ref output);
            },
            Option::None => {},
        }

        output.append(@"}");
    }
}

pub impl TcbComponentJson of JsonSerialize<TcbComponent> {
    fn serialize(value: @TcbComponent, ref output: ByteArray) {
        output.append(@"{");

        // svn
        append_json_field_name(@"svn", ref output);
        append_json_number(value.svn, ref output);

        // category (optional)
        match value.category {
            Option::Some(category) => {
                output.append(@",");
                append_json_field_name(@"category", ref output);
                append_json_string(category, ref output);
            },
            Option::None => {},
        }

        // type (optional)
        match value.type_ {
            Option::Some(type_) => {
                output.append(@",");
                append_json_field_name(@"type", ref output);
                append_json_string(type_, ref output);
            },
            Option::None => {},
        }

        output.append(@"}");
    }
}

pub impl TdxModuleIdentitiesArrayJson of JsonSerialize<Array<TdxModuleIdentities>> {
    fn serialize(value: @Array<TdxModuleIdentities>, ref output: ByteArray) {
        output.append(@"[");

        let mut first = true;
        let len = value.len();
        let mut i = 0;
        while i < len {
            if !first {
                output.append(@",");
            }
            JsonSerialize::<TdxModuleIdentities>::serialize(value.at(i), ref output);
            first = false;
            i += 1;
        }

        output.append(@"]");
    }
}

pub impl TdxModuleIdentitiesTcbLevelItemArrayJson of JsonSerialize<
    Array<TdxModuleIdentitiesTcbLevelItem>,
> {
    fn serialize(value: @Array<TdxModuleIdentitiesTcbLevelItem>, ref output: ByteArray) {
        output.append(@"[");

        let mut first = true;
        let len = value.len();
        let mut i = 0;
        while i < len {
            if !first {
                output.append(@",");
            }
            JsonSerialize::<TdxModuleIdentitiesTcbLevelItem>::serialize(value.at(i), ref output);
            first = false;
            i += 1;
        }

        output.append(@"]");
    }
}

pub impl TcbInfoV3TcbLevelItemArrayJson of JsonSerialize<Array<TcbInfoV3TcbLevelItem>> {
    fn serialize(value: @Array<TcbInfoV3TcbLevelItem>, ref output: ByteArray) {
        output.append(@"[");

        let mut first = true;
        let len = value.len();
        let mut i = 0;
        while i < len {
            if !first {
                output.append(@",");
            }
            JsonSerialize::<TcbInfoV3TcbLevelItem>::serialize(value.at(i), ref output);
            first = false;
            i += 1;
        }

        output.append(@"]");
    }
}

pub impl TcbComponentArrayJson of JsonSerialize<Array<TcbComponent>> {
    fn serialize(value: @Array<TcbComponent>, ref output: ByteArray) {
        output.append(@"[");

        let mut first = true;
        let len = value.len();
        let mut i = 0;
        while i < len {
            if !first {
                output.append(@",");
            }
            JsonSerialize::<TcbComponent>::serialize(value.at(i), ref output);
            first = false;
            i += 1;
        }

        output.append(@"]");
    }
}

/// Appends a JSON string value to the output, including quotes and escaping.
fn append_json_string(value: @ByteArray, ref output: ByteArray) {
    output.append(@"\"");
    output.append(value);
    output.append(@"\"");
}

/// Appends bytes as a hex string (uppercase, no prefix).
fn append_json_hex_bytes(bytes: @Span<u8>, ref output: ByteArray) {
    output.append(@"\"");

    let mut iter = bytes.clone();
    while let Option::Some(byte) = iter.pop_front() {
        // High nibble
        let high = *byte / 16;
        if high < 10 {
            output.append(@format!("{}", high));
        } else if high == 10 {
            output.append(@"A");
        } else if high == 11 {
            output.append(@"B");
        } else if high == 12 {
            output.append(@"C");
        } else if high == 13 {
            output.append(@"D");
        } else if high == 14 {
            output.append(@"E");
        } else if high == 15 {
            output.append(@"F");
        }

        // Low nibble
        let low = *byte % 16;
        if low < 10 {
            output.append(@format!("{}", low));
        } else if low == 10 {
            output.append(@"A");
        } else if low == 11 {
            output.append(@"B");
        } else if low == 12 {
            output.append(@"C");
        } else if low == 13 {
            output.append(@"D");
        } else if low == 14 {
            output.append(@"E");
        } else if low == 15 {
            output.append(@"F");
        }
    }

    output.append(@"\"");
}

/// Appends bytes as a hex string (lowercase, no prefix).
fn append_json_hex_bytes_lowercase(bytes: @Span<u8>, ref output: ByteArray) {
    output.append(@"\"");

    let mut iter = bytes.clone();
    while let Option::Some(byte) = iter.pop_front() {
        append_hex_byte_lowercase(*byte, ref output);
    }

    output.append(@"\"");
}

/// Appends a single byte in 2-character lower case hex representation.
pub(crate) fn append_hex_byte_lowercase(byte: u8, ref output: ByteArray) {
    // High nibble
    let high = byte / 16;
    if high < 10 {
        output.append(@format!("{}", high));
    } else if high == 10 {
        output.append(@"a");
    } else if high == 11 {
        output.append(@"b");
    } else if high == 12 {
        output.append(@"c");
    } else if high == 13 {
        output.append(@"d");
    } else if high == 14 {
        output.append(@"e");
    } else if high == 15 {
        output.append(@"f");
    }

    // Low nibble
    let low = byte % 16;
    if low < 10 {
        output.append(@format!("{}", low));
    } else if low == 10 {
        output.append(@"a");
    } else if low == 11 {
        output.append(@"b");
    } else if low == 12 {
        output.append(@"c");
    } else if low == 13 {
        output.append(@"d");
    } else if low == 14 {
        output.append(@"e");
    } else if low == 15 {
        output.append(@"f");
    }
}

/// Appends a JSON number value to the output.
fn append_json_number<T, +core::fmt::Display<T>, +Drop<T>>(value: @T, ref output: ByteArray) {
    // Use core::fmt::Display to format the number
    output.append(@format!("{}", value));
}

/// Appends a JSON field name (with colon).
fn append_json_field_name(name: @ByteArray, ref output: ByteArray) {
    append_json_string(name, ref output);
    output.append(@":");
}

/// Format OffsetDateTime as ISO 8601 UTC string
/// Output format: YYYY-MM-DDTHH:MM:SSZ
// CAIRO: Custom implementation for JSON serialization since time crate doesn't have this formatter
fn format_iso8601_utc(dt: @OffsetDateTime) -> ByteArray {
    let mut result = "";

    // Year (4 digits)
    format_padded(dt.year().try_into().unwrap(), 4, ref result);
    result.append(@"-");

    // Month (2 digits)
    let month_num: u8 = dt.month().into();
    format_padded(month_num.into(), 2, ref result);
    result.append(@"-");

    // Day (2 digits)
    format_padded(dt.day().into(), 2, ref result);
    result.append(@"T");

    // Hour (2 digits)
    format_padded(dt.time().hour().into(), 2, ref result);
    result.append(@":");

    // Minute (2 digits)
    format_padded(dt.time().minute().into(), 2, ref result);
    result.append(@":");

    // Second (2 digits)
    format_padded(dt.time().second().into(), 2, ref result);
    result.append(@"Z");

    result
}

/// Format number with zero-padding
fn format_padded(value: u32, width: u32, ref output: ByteArray) {
    let mut digits = array![];
    let mut n = value;

    // Extract digits
    if n == 0 {
        digits.append(0);
    } else {
        while n > 0 {
            digits.append(n % 10);
            n = n / 10;
        };
    }

    // Pad with zeros
    let mut padding = width - digits.len();
    while padding > 0 {
        output.append(@"0");
        padding -= 1;
    }

    // Output digits in reverse order
    let mut i = digits.len();
    while i > 0 {
        i -= 1;
        let digit = *digits[i];
        if digit == 0 {
            output.append(@"0");
        } else if digit == 1 {
            output.append(@"1");
        } else if digit == 2 {
            output.append(@"2");
        } else if digit == 3 {
            output.append(@"3");
        } else if digit == 4 {
            output.append(@"4");
        } else if digit == 5 {
            output.append(@"5");
        } else if digit == 6 {
            output.append(@"6");
        } else if digit == 7 {
            output.append(@"7");
        } else if digit == 8 {
            output.append(@"8");
        } else if digit == 9 {
            output.append(@"9");
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_identity_json() {
        let mut json: ByteArray = "";
        JsonSerialize::<
            EnclaveIdentityV2Inner,
        >::serialize(@crate::data::qeidentityv2_apiv4::data().enclave_identity, ref json);

        assert_eq!(
            json,
            "{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2025-02-13T03:39:00Z\",\"nextUpdate\":\"2025-03-15T03:39:00Z\",\"tcbEvaluationDataNumber\":17,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5\",\"isvprodid\":2,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]}",
        );
    }

    #[test]
    fn test_tcb_info_json() {
        let mut json: ByteArray = "";
        JsonSerialize::<
            TcbInfoV3Inner,
        >::serialize(@crate::data::tcbinfov3_00806f050000::data().tcb_info, ref json);

        assert_eq!(
            json,
            "{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2025-02-13T03:50:41Z\",\"nextUpdate\":\"2025-03-15T03:50:41Z\",\"fmspc\":\"00806f050000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":17,\"tdxModule\":{\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"},\"tdxModuleIdentities\":[{\"id\":\"TDX_03\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":3},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]},{\"id\":\"TDX_01\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"isvsvn\":2},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}],\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":7,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":7,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":1,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":11,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":7,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":6,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":6,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":1,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":11,\"tdxtcbcomponents\":[{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":6,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00960\",\"INTEL-SA-00982\",\"INTEL-SA-00986\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":5,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":1,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":11,\"tdxtcbcomponents\":[{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2023-02-15T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00837\",\"INTEL-SA-00960\",\"INTEL-SA-00982\",\"INTEL-SA-00986\"]},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":5,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":3,\"category\":\"BIOS\"},{\"svn\":1,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":5,\"tdxtcbcomponents\":[{\"svn\":3,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2018-01-04T00:00:00Z\",\"tcbStatus\":\"OutOfDate\",\"advisoryIDs\":[\"INTEL-SA-00106\",\"INTEL-SA-00115\",\"INTEL-SA-00135\",\"INTEL-SA-00203\",\"INTEL-SA-00220\",\"INTEL-SA-00233\",\"INTEL-SA-00270\",\"INTEL-SA-00293\",\"INTEL-SA-00320\",\"INTEL-SA-00329\",\"INTEL-SA-00381\",\"INTEL-SA-00389\",\"INTEL-SA-00477\",\"INTEL-SA-00837\",\"INTEL-SA-00960\",\"INTEL-SA-00982\",\"INTEL-SA-00986\"]}]}",
        );
    }
}
