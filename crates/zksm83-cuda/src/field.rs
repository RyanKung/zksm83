use jolt_field::{CanonicalEncoding, Prime128OffsetA7F7};

const REDUCTION_OFFSET: u64 = 0xffff_a7f7;
const MODULUS_LOW: u64 = 0_u64.wrapping_sub(REDUCTION_OFFSET);

/// Canonical two-limb representation of the native Akita base field.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct FieldElement {
    low: u64,
    high: u64,
}

impl FieldElement {
    /// Constructs a field element when the two limbs are below the modulus.
    #[must_use]
    pub const fn from_canonical_limbs(low: u64, high: u64) -> Option<Self> {
        if high != u64::MAX || low < MODULUS_LOW {
            Some(Self { low, high })
        } else {
            None
        }
    }

    /// Converts the native Jolt field representation into device limbs.
    #[must_use]
    pub fn from_native(value: Prime128OffsetA7F7) -> Self {
        let [low, high] = value.to_limbs();
        Self { low, high }
    }

    /// Converts canonical device limbs back into the native Jolt field.
    #[must_use]
    pub fn to_native(self) -> Option<Prime128OffsetA7F7> {
        let value = u128::from(self.low) | (u128::from(self.high) << 64);
        Prime128OffsetA7F7::from_u128_checked(value)
    }

    /// Returns the canonical little-endian limbs used at the CUDA ABI boundary.
    #[must_use]
    pub const fn limbs(self) -> [u64; 2] {
        [self.low, self.high]
    }

    /// Adds two canonical field elements modulo the Akita base-field prime.
    #[must_use]
    pub fn add_mod(self, rhs: Self) -> Self {
        let (low, carry_low) = self.low.overflowing_add(rhs.low);
        let (high_without_carry, carry_high_a) = self.high.overflowing_add(rhs.high);
        let (high, carry_high_b) = high_without_carry.overflowing_add(u64::from(carry_low));
        canonicalize_after_add(low, high, carry_high_a | carry_high_b)
    }

    /// Subtracts two canonical field elements modulo the Akita base-field prime.
    #[must_use]
    pub fn sub_mod(self, rhs: Self) -> Self {
        let (low, borrow_low) = self.low.overflowing_sub(rhs.low);
        let (high_without_borrow, borrow_high_a) = self.high.overflowing_sub(rhs.high);
        let (high, borrow_high_b) = high_without_borrow.overflowing_sub(u64::from(borrow_low));
        if borrow_high_a | borrow_high_b {
            subtract_reduction_offset(low, high)
        } else {
            Self { low, high }
        }
    }

    /// Multiplies two canonical field elements using two-fold Solinas reduction.
    #[must_use]
    pub fn mul_mod(self, rhs: Self) -> Self {
        let [r0, r1, r2, r3] = multiply_wide(self, rhs);
        reduce_wide(r0, r1, r2, r3)
    }

    /// Evaluates `low + challenge * (high - low)` in the native field.
    #[must_use]
    pub fn fold(low: Self, high: Self, challenge: Self) -> Self {
        low.add_mod(challenge.mul_mod(high.sub_mod(low)))
    }
}

fn canonicalize_after_add(low: u64, high: u64, overflow: bool) -> FieldElement {
    let (reduced_low, carry_low) = low.overflowing_add(REDUCTION_OFFSET);
    let (reduced_high, carry_high) = high.overflowing_add(u64::from(carry_low));
    if overflow | carry_high {
        FieldElement {
            low: reduced_low,
            high: reduced_high,
        }
    } else {
        FieldElement { low, high }
    }
}

fn subtract_reduction_offset(low: u64, high: u64) -> FieldElement {
    let (reduced_low, borrow) = low.overflowing_sub(REDUCTION_OFFSET);
    FieldElement {
        low: reduced_low,
        high: high.wrapping_sub(u64::from(borrow)),
    }
}

fn multiply_wide(lhs: FieldElement, rhs: FieldElement) -> [u64; 4] {
    let (r0, carry0) = lhs.low.carrying_mul(rhs.low, 0);
    let (r1_partial, carry1) = lhs.low.carrying_mul_add(rhs.high, carry0, 0);
    let (r1, carry2) = lhs.high.carrying_mul_add(rhs.low, 0, r1_partial);
    let (r2, r3) = lhs.high.carrying_mul_add(rhs.high, carry1, carry2);
    [r0, r1, r2, r3]
}

fn multiply_offset_wide(value: u64) -> (u64, u64) {
    REDUCTION_OFFSET.carrying_mul(value, 0)
}

fn reduce_wide(r0: u64, r1: u64, r2: u64, r3: u64) -> FieldElement {
    let (offset_r2_low, offset_r2_high) = multiply_offset_wide(r2);
    let (offset_r3_low, offset_r3_high) = multiply_offset_wide(r3);

    let (t0, carry0) = r0.overflowing_add(offset_r2_low);
    let (t1_a, carry1_a) = r1.overflowing_add(offset_r2_high);
    let (t1_b, carry1_b) = t1_a.overflowing_add(offset_r3_low);
    let (t1, carry1_c) = t1_b.overflowing_add(u64::from(carry0));
    let t2 = offset_r3_high
        .wrapping_add(u64::from(carry1_a))
        .wrapping_add(u64::from(carry1_b))
        .wrapping_add(u64::from(carry1_c));
    fold_high_limb(t0, t1, t2)
}

fn fold_high_limb(t0: u64, t1: u64, t2: u64) -> FieldElement {
    let (offset_t2_low, offset_t2_high) = multiply_offset_wide(t2);
    let (sum_low, carry_low) = t0.overflowing_add(offset_t2_low);
    let (sum_high_a, carry_high_a) = t1.overflowing_add(offset_t2_high);
    let (sum_high, carry_high_b) = sum_high_a.overflowing_add(u64::from(carry_low));
    canonicalize_after_add(sum_low, sum_high, carry_high_a | carry_high_b)
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, MODULUS_LOW, REDUCTION_OFFSET, multiply_wide};
    use jolt_field::{CanonicalEncoding, Prime128OffsetA7F7};

    #[test]
    fn canonical_constructor_rejects_the_modulus() {
        assert!(FieldElement::from_canonical_limbs(MODULUS_LOW, u64::MAX).is_none());
        assert!(
            FieldElement::from_canonical_limbs(MODULUS_LOW.wrapping_sub(1), u64::MAX).is_some()
        );
    }

    #[test]
    fn widening_multiply_matches_the_integer_product() {
        let mut state = 0x5a17_3d49_c208_ef61_u64;
        for _ in 0..10_000 {
            let left = next_u128(&mut state);
            let right = next_u128(&mut state);
            let lhs = FieldElement {
                low: left as u64,
                high: (left >> 64) as u64,
            };
            let rhs = FieldElement {
                low: right as u64,
                high: (right >> 64) as u64,
            };
            let [r0, r1, r2, r3] = multiply_wide(lhs, rhs);
            let low_product = u128::from(r0) | (u128::from(r1) << 64);
            let high_product = u128::from(r2) | (u128::from(r3) << 64);
            assert_eq!(low_product, left.wrapping_mul(right));
            assert_eq!(high_product, carrying_product_high(left, right));
        }
    }

    #[test]
    fn device_field_arithmetic_matches_native_field() {
        let mut state = 0xe7b9_85d1_32af_04c3_u64;
        for _ in 0..10_000 {
            let left_native = Prime128OffsetA7F7::from_u128_reduced(next_u128(&mut state));
            let right_native = Prime128OffsetA7F7::from_u128_reduced(next_u128(&mut state));
            let challenge_native = Prime128OffsetA7F7::from_u128_reduced(next_u128(&mut state));
            let left = FieldElement::from_native(left_native);
            let right = FieldElement::from_native(right_native);
            let challenge = FieldElement::from_native(challenge_native);

            assert_eq!(
                left.add_mod(right).to_native(),
                Some(left_native + right_native)
            );
            assert_eq!(
                left.sub_mod(right).to_native(),
                Some(left_native - right_native)
            );
            assert_eq!(
                left.mul_mod(right).to_native(),
                Some(left_native * right_native)
            );
            assert_eq!(
                FieldElement::fold(left, right, challenge).to_native(),
                Some(left_native + challenge_native * (right_native - left_native))
            );
        }
    }

    #[test]
    fn reduction_handles_modulus_boundaries() {
        let modulus = u128::MAX - u128::from(REDUCTION_OFFSET) + 1;
        let zero = Prime128OffsetA7F7::from_u128_reduced(0);
        let one = Prime128OffsetA7F7::from_u128_reduced(1);
        let maximum = Prime128OffsetA7F7::from_u128_reduced(modulus - 1);
        let zero_device = FieldElement::from_native(zero);
        let one_device = FieldElement::from_native(one);
        let maximum_device = FieldElement::from_native(maximum);

        assert_eq!(maximum_device.add_mod(one_device).to_native(), Some(zero));
        assert_eq!(zero_device.sub_mod(one_device).to_native(), Some(maximum));
        assert_eq!(
            maximum_device.mul_mod(maximum_device).to_native(),
            Some(one)
        );
    }

    fn next_u64(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn next_u128(state: &mut u64) -> u128 {
        u128::from(next_u64(state)) | (u128::from(next_u64(state)) << 64)
    }

    fn carrying_product_high(left: u128, right: u128) -> u128 {
        let left_low = left as u64;
        let left_high = (left >> 64) as u64;
        let right_low = right as u64;
        let right_high = (right >> 64) as u64;
        let (_, carry0) = left_low.carrying_mul(right_low, 0);
        let (middle, carry1) = left_low.carrying_mul_add(right_high, carry0, 0);
        let (_, carry2) = left_high.carrying_mul_add(right_low, 0, middle);
        let (high_low, high_high) = left_high.carrying_mul_add(right_high, carry1, carry2);
        u128::from(high_low) | (u128::from(high_high) << 64)
    }
}
