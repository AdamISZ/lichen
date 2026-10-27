//! Boolean circuits, as the garbler garbles them: XOR, AND and NOT gates
//! over numbered wires, the inputs first, then one wire a gate. The
//! builder folds constants away, so a gadget written over constant bits
//! (a modulus, a fallback point) costs only its wires' gates.

/// A wire's number: the inputs are `0..inputs`, gate `g`'s output is
/// `inputs + g`.
pub type Wire = u32;

/// A bit while building: a constant, or a wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bit {
    Const(bool),
    Wire(Wire),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Xor(Wire, Wire),
    And(Wire, Wire),
    Not(Wire),
}

#[derive(Clone, Debug)]
pub struct Circuit {
    pub inputs: usize,
    pub gates: Vec<Gate>,
    pub outputs: Vec<Wire>,
}

impl Circuit {
    /// The AND gates: the garbled ones, one ciphertext each.
    pub fn ands(&self) -> usize {
        self.gates.iter().filter(|g| matches!(g, Gate::And(..))).count()
    }

    /// Every wire's value: the inputs', then each gate's.
    pub fn values(&self, input: &[bool]) -> Vec<bool> {
        assert_eq!(input.len(), self.inputs);
        let mut v = Vec::with_capacity(self.inputs + self.gates.len());
        v.extend_from_slice(input);
        for g in &self.gates {
            let x = match *g {
                Gate::Xor(a, b) => v[a as usize] ^ v[b as usize],
                Gate::And(a, b) => v[a as usize] & v[b as usize],
                Gate::Not(a) => !v[a as usize],
            };
            v.push(x);
        }
        v
    }

    pub fn eval(&self, input: &[bool]) -> Vec<bool> {
        let v = self.values(input);
        self.outputs.iter().map(|w| v[*w as usize]).collect()
    }
}

pub struct Builder {
    inputs: usize,
    gates: Vec<Gate>,
}

impl Builder {
    /// A builder with `inputs` input wires, and those wires.
    pub fn new(inputs: usize) -> (Builder, Vec<Bit>) {
        (Builder { inputs, gates: Vec::new() }, (0..inputs as Wire).map(Bit::Wire).collect())
    }

    fn gate(&mut self, g: Gate) -> Bit {
        self.gates.push(g);
        Bit::Wire((self.inputs + self.gates.len() - 1) as Wire)
    }

    pub fn xor(&mut self, a: Bit, b: Bit) -> Bit {
        match (a, b) {
            (Bit::Const(x), Bit::Const(y)) => Bit::Const(x ^ y),
            (Bit::Const(false), w) | (w, Bit::Const(false)) => w,
            (Bit::Const(true), w) | (w, Bit::Const(true)) => self.not(w),
            (Bit::Wire(x), Bit::Wire(y)) if x == y => Bit::Const(false),
            (Bit::Wire(x), Bit::Wire(y)) => self.gate(Gate::Xor(x, y)),
        }
    }

    pub fn and(&mut self, a: Bit, b: Bit) -> Bit {
        match (a, b) {
            (Bit::Const(x), Bit::Const(y)) => Bit::Const(x & y),
            (Bit::Const(false), _) | (_, Bit::Const(false)) => Bit::Const(false),
            (Bit::Const(true), w) | (w, Bit::Const(true)) => w,
            (Bit::Wire(x), Bit::Wire(y)) if x == y => a,
            (Bit::Wire(x), Bit::Wire(y)) => self.gate(Gate::And(x, y)),
        }
    }

    pub fn not(&mut self, a: Bit) -> Bit {
        match a {
            Bit::Const(x) => Bit::Const(!x),
            Bit::Wire(x) => self.gate(Gate::Not(x)),
        }
    }

    pub fn or(&mut self, a: Bit, b: Bit) -> Bit {
        let x = self.xor(a, b);
        let y = self.and(a, b);
        self.xor(x, y)
    }

    /// `a` if `s`, else `b`: one AND.
    pub fn mux(&mut self, s: Bit, a: Bit, b: Bit) -> Bit {
        let d = self.xor(a, b);
        let t = self.and(s, d);
        self.xor(b, t)
    }

    /// The circuit, its outputs `outputs`: wires, not constants (a garbled
    /// output is a label).
    pub fn finish(self, outputs: &[Bit]) -> Circuit {
        let outputs = outputs
            .iter()
            .map(|b| match b {
                Bit::Wire(w) => *w,
                Bit::Const(_) => panic!("a constant output"),
            })
            .collect();
        Circuit { inputs: self.inputs, gates: self.gates, outputs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_fold() {
        let (mut b, i) = Builder::new(2);
        let t = Bit::Const(true);
        assert_eq!(b.and(i[0], Bit::Const(false)), Bit::Const(false));
        assert_eq!(b.and(i[0], t), i[0]);
        assert_eq!(b.xor(i[1], i[1]), Bit::Const(false));
        assert!(b.gates.is_empty());
        let x = b.xor(i[0], t);
        let m = b.mux(i[1], x, i[0]);
        let c = b.finish(&[x, m]);
        for (p, q) in [(false, false), (false, true), (true, false), (true, true)] {
            assert_eq!(c.eval(&[p, q]), [!p, if q { !p } else { p }]);
        }
        assert_eq!(c.ands(), 1);
    }
}
