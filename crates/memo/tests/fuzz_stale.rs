//! Staleness fuzz: apply random mutation sequences to the inputs and, after each
//! step, assert memo's result (stdout + output file) equals what a real run would
//! produce for the current input state. A replay that ever disagrees with ground
//! truth is a staleness bug — the one failure mode memo must never have.

mod it_util;
use it_util::{abs, Sandbox};

/// Tiny deterministic PRNG (xorshift) so failures reproduce.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn expected_output(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> (Vec<u8>, String) {
    let av = a.clone().unwrap_or_default();
    let bv = b.clone().unwrap_or_default();
    let mut out = av.clone();
    out.extend_from_slice(&bv);
    let stdout = format!("CONCAT {} {} {}\n", av.len(), bv.len(), out.len());
    (out, stdout)
}

#[test]
fn random_mutations_never_replay_stale() {
    let sb = Sandbox::new("fuzz_stale");
    let a_path = abs(&sb.path("a.txt"));
    let b_path = abs(&sb.path("b.txt"));
    let out_path = abs(&sb.path("out.bin"));
    let op = format!("concat={}|{}|{}", a_path, b_path, out_path);

    // Model of current input state.
    let mut a: Option<Vec<u8>> = None;
    let mut b: Option<Vec<u8>> = None;

    // MEMO_FUZZ_SEED explores other sequences (must be non-zero for xorshift).
    let seed = std::env::var("MEMO_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x9E3779B97F4A7C15);
    let mut rng = Rng(seed);
    let values: [&[u8]; 4] = [b"", b"x", b"hello", b"a-longer-value-here"];

    for step in 0..120u32 {
        // Apply one random mutation to a or b.
        let target_a = rng.below(2) == 0;
        let action = rng.below(3); // 0=set, 1=delete, 2=set-different
        let file = if target_a { "a.txt" } else { "b.txt" };
        let slot = if target_a { &mut a } else { &mut b };
        match action {
            1 => {
                let _ = std::fs::remove_file(sb.path(file));
                *slot = None;
            }
            _ => {
                let v = values[rng.below(values.len() as u64) as usize].to_vec();
                sb.write(file, &v);
                *slot = Some(v);
            }
        }
        // Ensure a distinct mtime for content changes.
        std::thread::sleep(std::time::Duration::from_millis(3));

        let (exp_out, exp_stdout) = expected_output(&a, &b);

        let r = sb.run(&[&op]);
        assert_eq!(r.exit, 0, "step {}: exit; stderr {}", step, r.stderr);
        assert_eq!(
            r.stdout,
            exp_stdout,
            "step {}: stdout mismatch (replayed={}, executed={})",
            step,
            r.replayed(),
            r.executed
        );
        let got_out = std::fs::read(sb.path("out.bin")).unwrap_or_default();
        assert_eq!(
            got_out,
            exp_out,
            "step {}: OUTPUT FILE MISMATCH — stale replay! (replayed={}, executed={})",
            step,
            r.replayed(),
            r.executed
        );
    }
}
