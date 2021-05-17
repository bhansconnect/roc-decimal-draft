#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RocDec {
    hi: i64, // high-order bits, including the sign
    lo: u64, // low-order bits
}

impl Into<String> for RocDec {
    fn into(self) -> String {
        return self.to_string();
    }
}

impl<'a> std::convert::TryFrom<&'a str> for RocDec {
    type Error = ();

    fn try_from(value: &'a str) -> Result<Self, ()> {
        // Split the string into the parts before and after the "."
        let mut parts = value.split(".");

        let before_point = match parts.next() {
            Some(answer) => answer,
            None => {
                return Err(());
            }
        };

        let after_point = match parts.next() {
            Some(answer) => answer,
            None => {
                return Err(());
            }
        };

        // There should have only been one "." in the string!
        if parts.next().is_some() {
            return Err(());
        }

        // The low bits need padding to parse.
        // TODO don't pad zeroes using format!() - unnecessary allocation!
        let lo = match format!("{:0<19}", after_point).parse::<u64>() {
            Ok(answer) => answer,
            Err(_) => {
                return Err(());
            }
        };

        match before_point.parse::<i64>() {
            Ok(hi) => Ok(RocDec { hi, lo }),
            Err(_) => {
                match before_point {
                    // This is a special case that's allowed - it's one lower than i64::MIN.
                    "-9223372036854775809" => {
                        //
                        // Move the bottom digit into the low bits,
                        // by setting hi to i64::MIN and adding DECIMAL_MAX to lo
                        match lo.checked_add(RocDec::DECIMAL_MAX) {
                            Some(lo) => Ok(RocDec { hi: i64::MIN, lo }),
                            None => Err(()),
                        }
                    }
                    // This is another special case that's allowed - it's one higher than i64::MAX.
                    "9223372036854775808" => {
                        // Move the bottom digit into the low bits,
                        // by setting hi to i64::MIN and adding DECIMAL_MAX to lo
                        match lo.checked_add(RocDec::DECIMAL_MAX) {
                            Some(lo) => Ok(RocDec { hi: i64::MAX, lo }),
                            None => Err(()),
                        }
                    }
                    // No special case applied; this is an ordinary failed parse
                    _ => Err(()),
                }
            }
        }
    }
}

impl std::ops::Add for RocDec {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        // Care has been taken to make this branchless by using cmov conditionals
        // only. The result is that it does a couple of operations that
        // wouldn't be necessary otherwise (specifically doing both an
        // overflowing_add and overflowing_sub due to not knowing which will be
        // needed), but overall this means there will never be any dramatic
        // variations in performance because of branch mispredictions, and that
        // it will be faster on average across all invocations.
        let other_hi = other.hi;
        let other_lo = other.lo;
        let self_hi = self.hi;
        let self_lo = self.lo;
        let self_is_positive = self_hi.is_positive();
        let other_is_positive = other_hi.is_positive();

        // Unfortunately, since these are u64 values, we actually need to
        // (situationally) do a subtraction instruction here. We can't just
        // negate them, because they might be too big to fit in an i64.
        //
        // To avoid branch mispredictions, we do both the add as well as
        // the sub operation. This means we're always paying +1 cycle, but
        // that's better than sometimes paying 0 and other times paying many.
        let (lo_added, add_overflowed) = self_lo.overflowing_add(other_lo);
        let (lo_subtracted, sub_overflowed) = self_lo.overflowing_sub(other_lo);
        let same_sign = self_is_positive == other_is_positive;
        let lo = if same_sign { lo_added } else { lo_subtracted };
        let hi_offset = {
            let hi_sign: i64 = if self_is_positive { 1 } else { -1 };
            let overflowed = if same_sign {
                add_overflowed
            } else {
                sub_overflowed
            };

            if overflowed {
                hi_sign
            } else {
                0
            }
        };

        let (hi, overflowed2) = self_hi.overflowing_add(hi_offset);
        let (hi, overflowed3) = hi.overflowing_add(other_hi);

        if overflowed2 || overflowed3 {
            todo!("TODO throw an error for overflow");
        }

        RocDec { hi, lo }
    }
}

impl std::ops::Sub for RocDec {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        // Care has been taken to make this branchless by using cmov conditionals
        // only. The result is that it does a couple of operations that
        // wouldn't be necessary otherwise (specifically doing both an
        // overflowing_add and overflowing_sub due to not knowing which will be
        // needed), but overall this means there will never be any dramatic
        // variations in performance because of branch mispredictions, and that
        // it will be faster on average across all invocations.
        let other_hi = other.hi;
        let other_lo = other.lo;
        let self_hi = self.hi;
        let self_lo = self.lo;
        let self_is_positive = self_hi.is_positive();
        let other_is_positive = other_hi.is_positive();

        // Unfortunately, since these are u64 values, we actually need to
        // (situationally) do a subtraction instruction here. We can't just
        // negate them, because they might be too big to fit in an i64.
        //
        // To avoid branch mispredictions, we do both the add as well as
        // the sub operation. This means we're always paying +1 cycle, but
        // that's better than sometimes paying 0 and other times paying many.
        let (lo_added, add_overflowed) = self_lo.overflowing_add(other_lo);
        let (lo_subtracted, sub_overflowed) = self_lo.overflowing_sub(other_lo);
        let same_sign = self_is_positive == other_is_positive;
        let lo = if same_sign { lo_subtracted } else { lo_added };
        let hi_offset = {
            let hi_sign: i64 = if self_is_positive { 1 } else { -1 };
            let overflowed = if same_sign {
                sub_overflowed
            } else {
                add_overflowed
            };

            if overflowed {
                hi_sign
            } else {
                0
            }
        };

        let (hi, overflowed2) = self_hi.overflowing_sub(hi_offset);
        let (hi, overflowed3) = hi.overflowing_sub(other_hi);

        if overflowed2 || overflowed3 {
            todo!("TODO throw an error for overflow");
        }

        RocDec { hi, lo }
    }
}

impl std::ops::Mul for RocDec {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let other_hi = other.hi;
        let other_lo = other.lo;
        let self_hi = self.hi;
        let self_lo = self.lo;

        // If they're both negative, or if neither is negative, the final answer
        // is positive or zero. If one is negative and the other isn't, the
        // final answer is negative (or zero, in which case final sign won't matter).
        //
        // It's important that we do this in terms of negatives, because doing
        // it in terms of positives instead causes bugs when both are 0.
        let final_is_negative = self_hi.is_negative() != other_hi.is_negative();

        let self_hi = match self_hi.checked_abs() {
            Some(answer) => answer as u64,
            None => {
                // TODO try to support some of these cases maybe?
                // Currently, if you try to do multiplication on i64::MIN, panic
                // unless you're specifically multiplying by 0 or 1.
                if other_hi == 0 && other_lo == 0 {
                    return RocDec { hi: 0, lo: 0 };
                } else if other_hi == 1 && other_lo == 0 {
                    return RocDec { hi: self_hi, lo: 0 };
                } else {
                    todo!("TODO overflow!");
                }
            }
        };

        let other_hi = match other_hi.checked_abs() {
            Some(answer) => answer as u64,
            None => {
                // TODO try to support some of these cases maybe?
                // Currently, if you try to do multiplication on i64::MIN, panic
                // unless you're specifically multiplying by 0 or 1.
                if self_hi == 0 && self_lo == 0 {
                    return RocDec { hi: 0, lo: 0 };
                } else if self_hi == 1 && self_lo == 0 {
                    return RocDec {
                        hi: other_hi,
                        lo: 0,
                    };
                } else {
                    todo!("TODO overflow!");
                }
            }
        };

        // Algorithm based on "Multiplication of larger integers" from:
        //
        // https://bisqwit.iki.fi/story/howto/bitmath/#MulUnsignedMultiplication
        //
        // That's where all the super short variable names like "ea" come from.

        // Impressively, this optimizes to the assembly instructions for
        // doing a "multiply two 64-bit integers and store the result as a
        // 128-bit integer" CPU instruction!
        //
        // https://godbolt.org/z/KnvchqP97
        //
        // Note that this cannot overflow; in fact, if you try to do an
        // overflowing_mul here, it gets optimized away!
        let ea = (self_lo as u128) * (other_lo as u128);

        // dbg!(ea);
        // println!("EA:\n{:#0128b}", ea);

        let (e, a) = decimalize(ea);

        // println!("e a:\n{:#064b}{:#064b}", e, a);

        let gf = (self_hi as u128) * (other_lo as u128);
        let (g, f) = decimalize(gf);

        let jh = (self_lo as u128) * (other_hi as u128);
        let (j, h) = decimalize(jh);

        let lk = (self_hi as u128) * (other_hi as u128);
        let (l, k) = decimalize(lk);

        //         println!("* self = hi {} lo {}", self_hi, self_lo);
        //         println!("* other = hi {} lo {}", other_hi, other_lo);

        //         println!(
        //             "* * * EA {} {} GF {} {} JH {} {} LK {} {}",
        //             e, a, g, f, j, h, l, k
        //         );

        // b = e + f + h
        let (e_plus_f, overflowed) = e.overflowing_add(f);
        let b_carry1 = if overflowed { 1 } else { 0 };
        let (b, overflowed) = e_plus_f.overflowing_add(h);
        let b_carry2 = if overflowed { 1 } else { 0 };

        // c = carry + g + j + k // it doesn't say +k but I think it should be?
        let (g_plus_j, overflowed) = g.overflowing_add(j);
        let c_carry1 = if overflowed { 1 } else { 0 };
        let (g_plus_j_plus_k, overflowed) = g_plus_j.overflowing_add(k); // it doesn't say +k but I think it should be?
        let c_carry2 = if overflowed { 1 } else { 0 };
        let (c_without_bcarry2, overflowed) = g_plus_j_plus_k.overflowing_add(b_carry1);
        let c_carry3 = if overflowed { 1 } else { 0 };
        let (c, overflowed) = c_without_bcarry2.overflowing_add(b_carry2);
        let c_carry4 = if overflowed { 1 } else { 0 };

        // d = carry + l
        let (d, overflowed1) = l.overflowing_add(c_carry1);
        let (d, overflowed2) = d.overflowing_add(c_carry2);
        let (d, overflowed3) = d.overflowing_add(c_carry3);
        let (d, overflowed4) = d.overflowing_add(c_carry4);

        // println!("    {}.{}", self_hi, self_lo);
        // println!("  x {}.{}", other_hi, other_lo);
        // println!("  -----");
        // println!(" =   {}{}", e, a);
        // println!("    {}{}", g, f);
        // println!("    {}{}", j, h);
        // println!(" + {}{}", l, k);
        // println!(" ------");
        // println!("   {}{}{}{}", d, c, b, a);

        //         println!("       {} {}", self_hi, self_lo);
        //         println!("     x {} {}", other_hi, other_lo);
        //         println!("     -----");
        //         println!(" =     {} {}", e, a);
        //         println!("     {} {}", g, f);
        //         println!("     {} {}", j, h);
        //         println!(" + {} {}", l, k);
        //         println!(" ------");
        //         println!("   {} {} {} {}", d, c, b, a);

        //         dbg!("DCBA = {}{}{}{}", d, c, b, a);

        // Since this is decimal multiplication, we "bit shift away" the lowest digits.
        let hi = if c <= i64::MAX as u64
            && d == 0
            && !(overflowed1 || overflowed2 || overflowed3 || overflowed4)
        {
            c as i64
        } else {
            todo!("Overflow!");
        };

        // This compiles to a cmov!
        let hi = if final_is_negative { -hi } else { hi };

        let lo = b;

        RocDec { hi, lo }
    }
}

/// A fixed-point decimal value with 19 decimal places of precision.
///
/// Why 19? Because 10^19 is the highest power of 10 that fits inside 2^64, and
/// being able to fit all the decimal digits into one u64 makes some operations
/// more efficient.
///
/// The lowest value it can store is -9223372036854775809.8446744073709551615
/// and the highest is 9223372036854775808.8446744073709551615
impl RocDec {
    /// The highest u64 where the first digit is 1 and every other digit is 0.
    const DECIMAL_MAX: u64 = 10_000_000_000_000_000_000;

    pub fn new(hi: i64, lo: u64) -> Self {
        RocDec { hi, lo }
    }

    pub fn to_string(self) -> String {
        let hi = self.hi;
        let lo = self.lo;

        // Next, we want to compute the number before the decimal point
        // and the number after the decimal point. hi and lo are almost there,
        // but not quite - because lo is supposed to hold 19 digits, but it can
        // potentially be higher than 19 nines. If it is, then:
        //
        // * we subtract (nineteen nines + 1) from lo
        // * we increase hi by 1
        //
        // At this point we now have hi being the full number before the decimal
        // point, and lo being the full number after the decimal point. We know
        // hi won't overflow from the increment, because we just changed it from
        // i64 to u64.

        // If lo is at least DECIMAL_MAX, then drop it down to all 9s (or lower)
        // by incrementing hi and subtracting DECIMAL_MAX from lo.
        let lo_offset = if lo >= Self::DECIMAL_MAX {
            Self::DECIMAL_MAX
        } else {
            0
        };
        let after_point = lo - lo_offset; // either the same or decreased by DECIMAL_MAX

        // TODO assuming lo needs all 19 digits, what's the highest hi
        // we can have that will fit in 24B, accounting for the minus sign
        // (if applicable) and the dot? What about 32B?
        let mut buf = String::with_capacity(64);

        // TODO switch to RocStr and account for small string optimization
        if hi.is_positive() {
            // It's positive, so casting to u64 is a no-op.
            // We need to cast to u64, because if it was previously isize::MAX,
            // we could potentially get signed integer overflow!
            let hi_offset: u64 = if lo_offset == 0 { 0 } else { 1 };
            let before_point = hi as u64 + hi_offset;

            // TODO do all this string logic without new allocations
            buf.push_str(&before_point.to_string());
        } else if hi != i64::MIN {
            // Since hi is not i64::MIN, we can (branchlessly) potentially
            // subtract 1 from it without any possibility of overflow.
            let hi_offset: u64 = if lo_offset == 0 { 0 } else { 1 };
            let before_point = hi - hi_offset as i64;

            // TODO do all this string logic without new allocations
            buf.push_str(&before_point.to_string());
        } else {
            // we're in the highly uncommon edge case where hi == i64::MIN,
            // which needs special-casing to avoid overflow.

            if lo_offset == 0 {
                // lo did not overflow, so we can just use i64::MIN
                buf.push_str("-9223372036854775808");
            } else {
                // This is 1 lower than i64::MIN, which would overflow if
                // we tried to store it as an i64 in memory, but which is fine
                // as long as we push it directly into the string.
                buf.push_str("-9223372036854775809");
            }
        }

        // TODO do all this by hand without more allocations or trim_matches()
        if after_point == 0 {
            // We special-case this because trim_matches would otherwise
            // trim it down to a trailing '.' alone, which is not what we want!
            buf.push_str(".0");
        } else {
            // pad zeroes and then trim trailing zeroes
            buf.push_str(&format!(".{:0>19}", after_point.to_string()).trim_matches('0'));
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use crate::RocDec;
    use std::convert::TryInto;
    use std::ops::{Add, Mul, Sub};

    fn assert_reflexive(hi: i64, lo: u64, expected_str: &str) {
        let dec = RocDec::new(hi, lo);
        let string = dec.to_string();

        assert_eq!(&string, expected_str);

        // There's more than one way to represent a given string as a RocDec,
        // but if we convert it into a RocDec and then back into a string again,
        // it should be the same as the original string.
        assert_eq!(
            Ok(RocDec::new(hi, lo).to_string()),
            string.as_str().try_into().map(RocDec::to_string)
        );
    }

    #[test]
    fn to_string() {
        // zero low bits
        assert_reflexive(0, 0, "0.0");
        assert_reflexive(1, 0, "1.0");
        assert_reflexive(-1, 0, "-1.0");
        assert_reflexive(10, 0, "10.0");
        assert_reflexive(-10, 0, "-10.0");
        assert_reflexive(360, 0, "360.0");
        assert_reflexive(-360, 0, "-360.0");

        // different sized high bits and low bits
        assert_reflexive(0, 1, "0.0000000000000000001");
        assert_reflexive(360, 1, "360.0000000000000000001");
        assert_reflexive(360, 100, "360.00000000000000001");
        assert_reflexive(360, 120, "360.000000000000000012");
        assert_reflexive(3600, 120, "3600.000000000000000012");

        // edge cases: what if there are more than 19 decimal digits stored
        // in the low bits?
        assert_reflexive(360, 9999999999999999999, "360.9999999999999999999");
        assert_reflexive(360, 10000000000000000000, "361.0");
        assert_reflexive(360, 10000000000000000001, "361.0000000000000000001");
        assert_reflexive(360, 10000000000000000042, "361.0000000000000000042");
        assert_reflexive(
            360,
            u64::MAX,
            &format!("361.{}", u64::MAX - RocDec::DECIMAL_MAX),
        );
        assert_reflexive(i64::MAX, 0, "9223372036854775807.0");
        assert_reflexive(i64::MIN, 0, "-9223372036854775808.0");
        assert_reflexive(
            i64::MAX,
            u64::MAX,
            "9223372036854775808.8446744073709551615",
        );
        assert_reflexive(
            i64::MIN,
            u64::MAX,
            "-9223372036854775809.8446744073709551615",
        );

        // TODO quickcheck test this, with negatives!!!
    }

    fn assert_added(hi1: i64, lo1: u64, hi2: i64, lo2: u64, expected: &str) {
        let dec1 = RocDec::new(hi1, lo1);
        let dec2 = RocDec::new(hi2, lo2);

        assert_eq!(expected, dec1.add(dec2).to_string());
    }

    fn assert_add(dec1: &str, dec2: &str, expected: &str) {
        let dec1: RocDec = dec1.try_into().unwrap();
        let dec2: RocDec = dec2.try_into().unwrap();

        assert_eq!(expected, dec1.add(dec2).to_string());
    }

    fn assert_subtracted(hi1: i64, lo1: u64, hi2: i64, lo2: u64, expected: &str) {
        let dec1 = RocDec::new(hi1, lo1);
        let dec2 = RocDec::new(hi2, lo2);

        assert_eq!(expected, dec1.sub(dec2).to_string());
    }

    fn assert_sub(dec1: &str, dec2: &str, expected: &str) {
        let dec1: RocDec = dec1.try_into().unwrap();
        let dec2: RocDec = dec2.try_into().unwrap();

        assert_eq!(expected, dec1.sub(dec2).to_string());
    }

    fn assert_multiplied(hi1: i64, lo1: u64, hi2: i64, lo2: u64, expected: &str) {
        let dec1 = RocDec::new(hi1, lo1);
        let dec2 = RocDec::new(hi2, lo2);

        assert_eq!(expected, dec1.mul(dec2).to_string());
    }

    fn assert_mul(dec1: &str, dec2: &str, expected: &str) {
        let dec1: RocDec = dec1.try_into().unwrap();
        let dec2: RocDec = dec2.try_into().unwrap();

        assert_eq!(expected, dec1.mul(dec2).to_string());
    }

    #[test]
    fn add() {
        // integers
        assert_added(0, 0, 0, 0, "0.0");
        assert_add("0.0", "0.0", "0.0");
        assert_added(360, 0, 360, 0, "720.0");
        assert_add("360.0", "360.0", "720.0");
        assert_added(123, 0, 456, 0, "579.0");
        assert_add("123.0", "456.0", "579.0");

        // non-integers
        assert_add("0.1", "0.2", "0.3");
        assert_added(111, 555, 222, 444, "333.0000000000000000999");
        assert_add(
            "111.0000000000000000555",
            "222.0000000000000000444",
            "333.0000000000000000999",
        );
    }

    #[test]
    fn sub() {
        // integers
        assert_subtracted(0, 0, 0, 0, "0.0");
        assert_sub("0.0", "0.0", "0.0");
        assert_subtracted(360, 0, 360, 0, "0.0");
        assert_sub("360.0", "360.0", "0.0");
        assert_subtracted(123, 0, 456, 0, "-333.0");
        assert_sub("123.0", "456.0", "-333.0");

        // non-integers
        assert_sub("0.3", "0.2", "0.1");
        assert_subtracted(111, 555, 222, 444, "-111.0000000000000000111");
        assert_sub(
            "111.0000000000000000555",
            "222.0000000000000000444",
            "-111.0000000000000000111",
        );
    }

    #[test]
    fn mul() {
        // integers
        assert_multiplied(0, 0, 0, 0, "0.0");
        assert_mul("0.0", "0.0", "0.0");
        assert_multiplied(2, 0, 3, 0, "6.0");
        assert_mul("2.0", "3.0", "6.0");
        assert_mul("2.0", "3.0", "6.0");
        assert_mul("15.0", "74.0", "1110.0");

        // non-integers
        assert_mul("1.1", "2.2", "2.42");
        assert_mul("2.0", "1.5", "3.0");
        assert_mul("2.3", "3.8", "8.74");
        assert_mul("1.01", "7.02", "7.0902");
        assert_mul("1.001", "7.002", "7.009002");
        assert_mul("1.0001", "7.0002", "7.00090002");
        assert_mul("1.00001", "7.00002", "7.0000900002");
        assert_mul("1.000001", "7.000002", "7.000009000002");
        assert_mul("1.0000001", "7.0000002", "7.00000090000002");
        assert_mul("1.00000001", "7.00000002", "7.0000000900000002");
        assert_mul("1.000000001", "7.000000002", "7.000000009000000002");
        assert_mul("-1.000000001", "7.000000002", "-7.000000009000000002");
        assert_mul("1.000000001", "-7.000000002", "-7.000000009000000002");
    }
}

#[inline(always)]
fn decimalize(num: u128) -> (u64, u64) {
    // let hi = (num / RocDec::DECIMAL_MAX as u128) as u64;
    // let lo = (num % RocDec::DECIMAL_MAX as u128) as u64;
    use ethnum::U256;
    let lhs = U256::from_words(0, num);

    // Instead multiply by the ceiling of 2^190/10^19 then divide by 2^190 (aka right shift)
    // 2^190/10^19 is 156927543384667019095894735580191660403
    let rhs = U256::from_words(0x0, 156927543384667019095894735580191660403);

    // I think this could theoretically be made faster due to discarded digits.
    // Would need to inline or manually write out the function.
    let res: U256 = lhs * rhs >> 190;

    // let hi = (*res.low() >> 64) as u64;
    let hi = res.as_u64();
    let lo = (num - (hi as u128 * RocDec::DECIMAL_MAX as u128)) as u64;
    (hi, lo)
}
