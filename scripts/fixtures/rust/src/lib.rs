pub fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        (a, b) = (b, a + b);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::fib;

    #[test]
    fn small() {
        assert_eq!(fib(0), 0);
        assert_eq!(fib(1), 1);
        assert_eq!(fib(10), 55);
    }

    #[test]
    fn larger() {
        assert_eq!(fib(50), 12_586_269_025);
    }
}
