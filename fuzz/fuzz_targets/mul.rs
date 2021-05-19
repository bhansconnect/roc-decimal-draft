#![no_main]
use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;
use ethnum::U256;

#[derive(Arbitrary, Debug)]
struct Data {
    a: i128,
    b: i128,
}

fuzz_target!(|data: Data| {
    let is_answer_negative = data.a.is_negative() != data.b.is_negative();

    let u256_a = match data.a.checked_abs() {
        Some(answer) => U256::new(answer as u128),
        // This ignores the edge case of match neg.
        // It should be handled for full fuzzing.
        None => return,
    };
    let u256_b = match data.b.checked_abs() {
        Some(answer) => U256::new(answer as u128),
        // This ignores the edge case of match neg.
        // It should be handled for full fuzzing.
        None => return,
    };
    let u256_out = u256_a * u256_b / U256::new(10u128.pow(18));
    if (*u256_out.high() > 0) || ((*u256_out.low() >> 127) > 0) {
        // This ignores the edge case of overflow during multiplication.
        // It should be handled for full fuzzing.
        return;
    }

    let dec_a = roc_dec::fuzz_new(data.a);
    let dec_b = roc_dec::fuzz_new(data.b);
    let dec_out = dec_a * dec_b;

    let expected_out = if is_answer_negative { -1i128 } else { 1i128 }
        * (*u256_out.low() & 0x7FFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFFu128) as i128;
    assert_eq!(roc_dec::fuzz_new(expected_out), dec_out);
    // dbg!(data);
});
