//! Port of bigint-validation.test.ts. The expected values are literals from the upstream `long` package.
use baileys::crypto;
use baileys::utils::generics::{Long, LongValue, long_to_number, long_to_string};
use waproto::pb::js_number;

fn check_string(low: i32, high: i32, unsigned: bool, expected: &str) {
    assert_eq!(long_to_string(LongValue::Long(Long::from_bits(low, high, unsigned)), unsigned), expected);
}
/// As upstream: both values may lose precision, so the check compares their string forms.
fn check_number(low: i32, high: i32, unsigned: bool, expected: &str) {
    assert_eq!(js_number(long_to_number(LongValue::Long(Long::from_bits(low, high, unsigned)), unsigned)), expected);
}
fn random_i32() -> i32 {
    let mut b = [0u8; 4];
    crypto::random_bytes(&mut b);
    i32::from_le_bytes(b)
}
/// The value of a Long by plain arithmetic, apart from how the implementation joins the two words.
fn exact(low: i32, high: i32, unsigned: bool) -> i128 {
    let lo = low as u32 as i128;
    let hi = if unsigned { high as u32 as i128 } else { high as i128 };
    hi * 4294967296 + lo
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_zero_unsigned_long_0_0_true() {
    check_string(0, 0, true, "0");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_zero_signed_long_0_0_false() {
    check_string(0, 0, false, "0");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_one_unsigned_long_1_0_true() {
    check_string(1, 0, true, "1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_one_signed_long_1_0_false() {
    check_string(1, 0, false, "1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_timestamp_2023_long_1700000000_0_true() {
    check_string(1700000000, 0, true, "1700000000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_timestamp_2025_long_1750000000_0_true() {
    check_string(1750000000, 0, true, "1750000000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_timestamp_as_signed_long_1700000000_0_false() {
    check_string(1700000000, 0, false, "1700000000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_small_file_long_1024_0_true() {
    check_string(1024, 0, true, "1024");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_medium_file_10mb_long_10485760_0_true() {
    check_string(10485760, 0, true, "10485760");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_large_file_2gb_long_2147483648_0_true() {
    check_string(-2147483648, 0, true, "2147483648");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_max_int32_long_2147483647_0_false() {
    check_string(2147483647, 0, false, "2147483647");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_min_int32_long_2147483648_1_false() {
    check_string(-2147483648, -1, false, "-2147483648");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_max_uint32_long_1_0_true() {
    check_string(-1, 0, true, "4294967295");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_max_safe_integer_long_1_2097151_false() {
    check_string(-1, 2097151, false, "9007199254740991");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_max_safe_integer_1_long_0_2097152_false() {
    check_string(0, 2097152, false, "9007199254740992");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_max_safe_integer_unsigned_long_1_2097151_true() {
    check_string(-1, 2097151, true, "9007199254740991");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_large_unsigned_long_1981284353_1966660860_true() {
    check_string(-1981284353, -1966660860, true, "9999999999999999999");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_max_uint64_long_1_1_true() {
    check_string(-1, -1, true, "18446744073709551615");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_max_uint64_1_long_2_1_true() {
    check_string(-2, -1, true, "18446744073709551614");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_negative_one_long_1_1_false() {
    check_string(-1, -1, false, "-1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_negative_small_long_100_1_false() {
    check_string(-100, -1, false, "-100");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_negative_large_long_2147483648_1_false() {
    check_string(-2147483648, -1, false, "-2147483648");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_min_int64_long_0_2147483648_false() {
    check_string(0, -2147483648, false, "-9223372036854775808");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_max_int64_long_1_2147483647_false() {
    check_string(-1, 2147483647, false, "9223372036854775807");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_1_as_signed_long_long_1_1_false() {
    check_string(-1, -1, false, "-1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_high_1_low_0_long_0_1_true() {
    check_string(0, 1, true, "4294967296");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_high_0_low_1_0xffffffff_long_1_0_true() {
    check_string(-1, 0, true, "4294967295");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_high_1_low_1_unsigned_max_uint64_long_1_1_true() {
    check_string(-1, -1, true, "18446744073709551615");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_high_0x7fffffff_low_0xffffffff_max_int64_long_1_2147483647_false() {
    check_string(-1, 2147483647, false, "9223372036854775807");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_high_0x80000000_low_0_min_int64_long_0_2147483648_false() {
    check_string(0, -2147483648, false, "-9223372036854775808");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_2_32_long_0_1_true() {
    check_string(0, 1, true, "4294967296");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_2_32_signed_long_0_1_false() {
    check_string(0, 1, false, "4294967296");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_2_48_long_0_65536_true() {
    check_string(0, 65536, true, "281474976710656");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtostring_equivalence_2_63_long_0_2147483648_true() {
    check_string(0, -2147483648, true, "9223372036854775808");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_zero_unsigned_long_0_0_true() {
    check_number(0, 0, true, "0");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_zero_signed_long_0_0_false() {
    check_number(0, 0, false, "0");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_one_unsigned_long_1_0_true() {
    check_number(1, 0, true, "1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_one_signed_long_1_0_false() {
    check_number(1, 0, false, "1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_timestamp_2023_long_1700000000_0_true() {
    check_number(1700000000, 0, true, "1700000000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_timestamp_2025_long_1750000000_0_true() {
    check_number(1750000000, 0, true, "1750000000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_timestamp_as_signed_long_1700000000_0_false() {
    check_number(1700000000, 0, false, "1700000000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_small_file_long_1024_0_true() {
    check_number(1024, 0, true, "1024");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_medium_file_10mb_long_10485760_0_true() {
    check_number(10485760, 0, true, "10485760");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_large_file_2gb_long_2147483648_0_true() {
    check_number(-2147483648, 0, true, "2147483648");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_max_int32_long_2147483647_0_false() {
    check_number(2147483647, 0, false, "2147483647");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_min_int32_long_2147483648_1_false() {
    check_number(-2147483648, -1, false, "-2147483648");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_max_uint32_long_1_0_true() {
    check_number(-1, 0, true, "4294967295");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_max_safe_integer_long_1_2097151_false() {
    check_number(-1, 2097151, false, "9007199254740991");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_max_safe_integer_1_long_0_2097152_false() {
    check_number(0, 2097152, false, "9007199254740992");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_max_safe_integer_unsigned_long_1_2097151_true() {
    check_number(-1, 2097151, true, "9007199254740991");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_large_unsigned_long_1981284353_1966660860_true() {
    check_number(-1981284353, -1966660860, true, "10000000000000000000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_max_uint64_long_1_1_true() {
    check_number(-1, -1, true, "18446744073709552000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_max_uint64_1_long_2_1_true() {
    check_number(-2, -1, true, "18446744073709552000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_negative_one_long_1_1_false() {
    check_number(-1, -1, false, "-1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_negative_small_long_100_1_false() {
    check_number(-100, -1, false, "-100");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_negative_large_long_2147483648_1_false() {
    check_number(-2147483648, -1, false, "-2147483648");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_min_int64_long_0_2147483648_false() {
    check_number(0, -2147483648, false, "-9223372036854776000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_max_int64_long_1_2147483647_false() {
    check_number(-1, 2147483647, false, "9223372036854776000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_1_as_signed_long_long_1_1_false() {
    check_number(-1, -1, false, "-1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_high_1_low_0_long_0_1_true() {
    check_number(0, 1, true, "4294967296");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_high_0_low_1_0xffffffff_long_1_0_true() {
    check_number(-1, 0, true, "4294967295");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_high_1_low_1_unsigned_max_uint64_long_1_1_true() {
    check_number(-1, -1, true, "18446744073709552000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_high_0x7fffffff_low_0xffffffff_max_int64_long_1_2147483647_false() {
    check_number(-1, 2147483647, false, "9223372036854776000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_high_0x80000000_low_0_min_int64_long_0_2147483648_false() {
    check_number(0, -2147483648, false, "-9223372036854776000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_2_32_long_0_1_true() {
    check_number(0, 1, true, "4294967296");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_2_32_signed_long_0_1_false() {
    check_number(0, 1, false, "4294967296");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_2_48_long_0_65536_true() {
    check_number(0, 65536, true, "281474976710656");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_longtonumber_equivalence_2_63_long_0_2147483648_true() {
    check_number(0, -2147483648, true, "9223372036854776000");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_non_long_inputs_fallback_paths_string_passthrough() {
    assert_eq!(long_to_string(LongValue::Str("12345"), false), "12345");
    assert_eq!(long_to_string(LongValue::Str("0"), false), "0");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_non_long_inputs_fallback_paths_number_passthrough() {
    assert_eq!(long_to_string(LongValue::Num(42.0), false), "42");
    assert_eq!(long_to_string(LongValue::Num(0.0), false), "0");
    assert_eq!(long_to_string(LongValue::Num(-1.0), false), "-1");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_non_long_inputs_fallback_paths_null_undefined_fallback() {
    assert_eq!(long_to_string(LongValue::Null, false), "null");
    assert_eq!(long_to_string(LongValue::Undefined, false), "undefined");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_non_long_inputs_fallback_paths_object_without_low_high() {
    // adapted: a JavaScript object has no Rust form, so LongValue::Object stands for `{ foo: 'bar' }`
    assert_eq!(long_to_string(LongValue::Object, false), "[object Object]");
}
#[test]
fn t_bigint_vs_long_equivalence_validation_fuzz_random_long_values_100_random_unsigned_values_match() {
    for _ in 0..100 {
        let (low, high) = (random_i32(), random_i32());
        // adapted: the reference is i128 arithmetic in place of the long package
        check_string(low, high, true, &exact(low, high, true).to_string());
    }
}
#[test]
fn t_bigint_vs_long_equivalence_validation_fuzz_random_long_values_100_random_signed_values_match() {
    for _ in 0..100 {
        let (low, high) = (random_i32(), random_i32());
        // adapted: the reference is i128 arithmetic in place of the long package
        check_string(low, high, false, &exact(low, high, false).to_string());
    }
}
