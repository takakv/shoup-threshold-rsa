use rug::Complete;
use std::ops::MulAssign;

pub fn shoup_delta(f: u32) -> rug::Integer {
    rug::Integer::factorial(f).complete()
}

fn lagrange_0_coefficient(current: i32, indices: &[i32]) -> (rug::Integer, rug::Integer) {
    let mut nominator = rug::Integer::from(1);
    let mut denominator = rug::Integer::from(1);

    for index in indices {
        if current == *index {
            continue;
        }

        nominator.mul_assign(index);
        denominator.mul_assign(index - current);
    }

    // Nom/denom is not necessarily an integer, but we always need integers.
    (nominator, denominator)
}

pub fn shoup_0_coefficient(
    current: u16,
    indices: &[i32],
    shoup_delta: &rug::Integer,
) -> rug::Integer {
    let (nominator, denominator) = lagrange_0_coefficient(current as i32, indices);
    (shoup_delta * nominator).div_exact(&denominator)
}
