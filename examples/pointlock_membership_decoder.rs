//! Offchain garbled exact-weight membership-to-lexicographic-rank decoder.
//! Free XOR plus four-row AND tables, BLAKE3 modeled as a correlation-robust
//! random oracle. Research reference, not a malicious-setup-verifiable GC.
#[path = "pointlock_decoders/mixed_radix.rs"]
pub(crate) mod mixed_radix;
use serde_json::json;
type Label = u128;
#[derive(Clone, Copy)]
struct Wire {
    id: usize,
    zero: Label,
}
#[derive(Clone)]
enum Gate {
    Xor(usize, usize),
    And(usize, usize, [Label; 4]),
}
#[derive(Clone)]
pub(crate) struct Decoder {
    pool: usize,
    n: usize,
    constant_zero: Label,
    gates: Vec<Gate>,
    outputs: Vec<usize>,
    output_commitments: Vec<[[u8; 32]; 2]>,
}
struct Builder {
    circuit: Decoder,
    delta: Label,
    wires: Vec<Wire>,
    private_seed: [u8; 32],
}
fn private_label(seed: &[u8; 32], id: usize) -> Label {
    let mut h = blake3::Hasher::new_keyed(seed);
    h.update(b"private-garbled-wire-label-v1");
    h.update(&(id as u64).to_le_bytes());
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}
fn commitment(x: Label) -> [u8; 32] {
    *blake3::hash(&x.to_le_bytes()).as_bytes()
}
fn hash(pool: usize, gate: usize, a: Label, b: Label) -> Label {
    let mut h = blake3::Hasher::new();
    h.update(b"bitcoin-lab/complement-membership-decoder/gate/v1");
    h.update(&(pool as u64).to_le_bytes());
    h.update(&(gate as u64).to_le_bytes());
    h.update(&a.to_le_bytes());
    h.update(&b.to_le_bytes());
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}
impl Builder {
    fn new(pool: usize, inputs: &[[Label; 2]], private_seed: [u8; 32]) -> Self {
        let delta = inputs[0][0] ^ inputs[0][1];
        assert_ne!(delta & 1, 0);
        assert!(inputs.iter().all(|p| p[0] ^ p[1] == delta));
        // The seed must remain secret for an unopened production garbling.
        let constant_zero = private_label(&private_seed, 0);
        let mut wires = vec![Wire {
            id: 0,
            zero: constant_zero,
        }];
        wires.extend(inputs.iter().enumerate().map(|(i, p)| Wire {
            id: i + 1,
            zero: p[0],
        }));
        Self {
            circuit: Decoder {
                pool,
                n: inputs.len(),
                constant_zero,
                gates: vec![],
                outputs: vec![],
                output_commitments: vec![],
            },
            delta,
            wires,
            private_seed,
        }
    }
    fn zero(&self) -> Wire {
        self.wires[0]
    }
    fn not(&self, a: Wire) -> Wire {
        Wire {
            id: a.id,
            zero: a.zero ^ self.delta,
        }
    }
    fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        let w = Wire {
            id: self.wires.len(),
            zero: a.zero ^ b.zero,
        };
        self.circuit.gates.push(Gate::Xor(a.id, b.id));
        self.wires.push(w);
        w
    }
    fn and(&mut self, a: Wire, b: Wire) -> Wire {
        let id = self.wires.len();
        let zero = private_label(&self.private_seed, id);
        let mut table = [0; 4];
        for x in 0..2 {
            for y in 0..2 {
                let al = a.zero ^ if x == 1 { self.delta } else { 0 };
                let bl = b.zero ^ if y == 1 { self.delta } else { 0 };
                let row = ((al & 1) * 2 + (bl & 1)) as usize;
                table[row] = hash(self.circuit.pool, id, al, bl)
                    ^ zero
                    ^ if x & y == 1 { self.delta } else { 0 };
            }
        }
        let w = Wire { id, zero };
        self.circuit.gates.push(Gate::And(a.id, b.id, table));
        self.wires.push(w);
        w
    }
    fn mux(&mut self, sel: Wire, a: Wire, b: Wire) -> Wire {
        let diff = self.xor(a, b);
        let part = self.and(sel, diff);
        self.xor(a, part)
    }
    fn add_masked_constant(&mut self, a: &[Wire], b: usize, sel: Wire) -> Vec<Wire> {
        let mut out = Vec::with_capacity(a.len());
        let mut carry = self.zero();
        for (i, &ai) in a.iter().enumerate() {
            if b >> i & 1 == 0 {
                out.push(self.xor(ai, carry));
                carry = self.and(ai, carry);
            } else {
                let ab = self.xor(ai, sel);
                out.push(self.xor(ab, carry));
                let first = self.and(ai, sel);
                let second = self.and(ab, carry);
                carry = self.xor(first, second);
            }
        }
        out
    }
    fn add(&mut self, a: &[Wire], b: &[Wire]) -> Vec<Wire> {
        let mut out = vec![];
        let mut carry = self.zero();
        for (&ai, &bi) in a.iter().zip(b) {
            let ab = self.xor(ai, bi);
            out.push(self.xor(ab, carry));
            let first = self.and(ai, bi);
            let second = self.and(ab, carry);
            carry = self.xor(first, second);
        }
        out
    }
    fn output(&mut self, w: Wire) {
        self.circuit.outputs.push(w.id);
        self.circuit
            .output_commitments
            .push([commitment(w.zero), commitment(w.zero ^ self.delta)]);
    }
}
fn choose(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    (0..k.min(n - k)).fold(1, |v, j| v * (n - j) / (j + 1))
}
pub(crate) fn build(
    pool: usize,
    inputs: &[[Label; 2]],
    t: usize,
    private_seed: [u8; 32],
) -> Decoder {
    let n = inputs.len();
    assert!(t > 0 && t < n && n <= 54);
    let capacity = choose(n, t);
    let bits = usize::BITS as usize - (capacity - 1).leading_zeros() as usize;
    let mut b = Builder::new(pool, inputs, private_seed);
    let zero = b.zero();
    let one = b.not(zero);
    let mut count = vec![zero; t + 1];
    count[0] = one;
    let mut sum = vec![zero; bits];
    for i in 0..n {
        let input = b.wires[i + 1];
        for k in 0..t {
            let constant = choose(n - i - 1, t - k);
            if constant != 0 {
                let selected = b.and(input, count[k]);
                sum = b.add_masked_constant(&sum, constant, selected);
            }
        }
        let mut next = vec![];
        for k in 0..=t {
            next.push(b.mux(input, count[k], if k == 0 { zero } else { count[k - 1] }));
        }
        count = next;
    }
    // Lex rank = C(n,t)-1-sum C(n-index-1,t-selected_before), mod 2^bits.
    let negsum: Vec<_> = sum.iter().map(|&w| b.not(w)).collect();
    let constant: Vec<_> = (0..bits)
        .map(|i| if capacity >> i & 1 == 1 { one } else { zero })
        .collect();
    let ranked = b.add(&negsum, &constant);
    for w in ranked {
        b.output(w);
    }
    b.output(count[t]);
    b.circuit
}
impl Decoder {
    pub(crate) fn evaluate(&self, labels: &[Label]) -> Option<Vec<Label>> {
        if labels.len() != self.n {
            return None;
        }
        let mut w = vec![self.constant_zero];
        w.extend_from_slice(labels);
        for gate in &self.gates {
            let id = w.len();
            let value = match gate {
                Gate::Xor(a, b) => w[*a] ^ w[*b],
                Gate::And(a, b, table) => {
                    let row = ((w[*a] & 1) * 2 + (w[*b] & 1)) as usize;
                    table[row] ^ hash(self.pool, id, w[*a], w[*b])
                }
            };
            w.push(value);
        }
        Some(self.outputs.iter().map(|&id| w[id]).collect())
    }
    pub(crate) fn decode_outputs(&self, labels: &[Label]) -> Option<(usize, bool)> {
        if labels.len() != self.output_commitments.len() {
            return None;
        }
        let mut bits = vec![];
        for (label, pair) in labels.iter().zip(&self.output_commitments) {
            bits.push(if commitment(*label) == pair[0] {
                0
            } else if commitment(*label) == pair[1] {
                1
            } else {
                return None;
            });
        }
        let valid = bits.pop()? == 1;
        Some((bits.iter().enumerate().map(|(i, b)| b << i).sum(), valid))
    }
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&(self.pool as u64).to_le_bytes());
        h.update(&(self.n as u64).to_le_bytes());
        h.update(&self.constant_zero.to_le_bytes());
        for g in &self.gates {
            match g {
                Gate::Xor(a, b) => {
                    h.update(&[0]);
                    h.update(&(*a as u64).to_le_bytes());
                    h.update(&(*b as u64).to_le_bytes());
                }
                Gate::And(a, b, t) => {
                    h.update(&[1]);
                    h.update(&(*a as u64).to_le_bytes());
                    h.update(&(*b as u64).to_le_bytes());
                    for v in t {
                        h.update(&v.to_le_bytes());
                    }
                }
            }
        }
        for (&id, pair) in self.outputs.iter().zip(&self.output_commitments) {
            h.update(&(id as u64).to_le_bytes());
            for c in pair {
                h.update(c);
            }
        }
        *h.finalize().as_bytes()
    }
    pub(crate) fn counts(&self) -> (usize, usize, usize) {
        let ands = self
            .gates
            .iter()
            .filter(|g| matches!(g, Gate::And(..)))
            .count();
        let xors = self.gates.len() - ands;
        (
            ands,
            xors,
            ands * 64 + 16 + self.output_commitments.len() * 64,
        )
    }
    pub(crate) fn same_tables(&self, other: &Self) -> bool {
        if self.pool != other.pool
            || self.n != other.n
            || self.constant_zero != other.constant_zero
            || self.outputs != other.outputs
            || self.output_commitments != other.output_commitments
            || self.gates.len() != other.gates.len()
        {
            return false;
        }
        self.gates
            .iter()
            .zip(&other.gates)
            .all(|(a, b)| match (a, b) {
                (Gate::Xor(x, y), Gate::Xor(v, w)) => x == v && y == w,
                (Gate::And(x, y, t), Gate::And(v, w, u)) => x == v && y == w && t == u,
                _ => false,
            })
    }
}
#[allow(dead_code)]
fn main() {
    let labels: Vec<_> = (0..50)
        .map(|i| {
            let z = hash(0, i, 100, 200);
            [z, z ^ 0xabcdef01]
        })
        .collect();
    let d = build(0, &labels, 4, [23; 32]);
    let (a, x, bytes) = d.counts();
    println!(
        "{}",
        json!({"and_gates":a,"xor_gates":x,"garbled_bytes":bytes,"scope":"Four-row AND tables plus one public constant label and both output-label hash commitments. Circuit topology is deterministic. No full verifier or malicious setup verification."})
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_eight_bit_input_has_correct_cardinality_and_valid_subsets_have_lex_rank() {
        let pairs: Vec<_> = (0..8)
            .map(|i| {
                let z = hash(0, i, 100, 200);
                [z, z ^ 0xabcdeff1]
            })
            .collect();
        let gc = build(0, &pairs, 4, [23; 32]);
        let mut checked = 0;
        for mask in 0u16..256 {
            let labels: Vec<_> = (0..8).map(|i| pairs[i][(mask >> i & 1) as usize]).collect();
            let (rank, valid) = gc.decode_outputs(&gc.evaluate(&labels).unwrap()).unwrap();
            assert_eq!(valid, mask.count_ones() == 4);
            if valid {
                let selected: Vec<_> = (0..8).filter(|i| mask >> i & 1 == 1).collect();
                let mut expected = 0;
                let mut start = 0;
                for (k, &i) in selected.iter().enumerate() {
                    for j in start..i {
                        expected += choose(8 - j - 1, 3 - k);
                    }
                    start = i + 1;
                }
                assert_eq!(rank, expected);
                checked += 1;
            }
        }
        assert_eq!(checked, 70);
    }
}
