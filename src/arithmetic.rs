use rug::Complete;
use std::ops::MulAssign;

pub fn shoup_delta(f: u32) -> rug::Integer {
    rug::Integer::factorial(f).complete()
}

fn lagrange_0_coefficient(current: i32, indices: &[i32]) -> rug::Integer {
    let mut nominator = rug::Integer::from(1);
    let mut denominator = rug::Integer::from(1);

    for index in indices {
        if current == *index {
            continue;
        }

        nominator.mul_assign(index);
        denominator.mul_assign(index - current);
    }

    nominator.div_exact(&denominator)
}

pub fn shoup_0_coefficient(
    current: u16,
    indices: &[i32],
    shoup_delta: &rug::Integer,
) -> rug::Integer {
    shoup_delta * lagrange_0_coefficient(current as i32, indices)
}
