pub fn expected(a: i64, b: i64) -> (i64, i64) {
    let sum = a + b;
    let class = if sum.abs() > BOUND { sum.signum() } else { 0 };
    (sum - class * BOUND, class)
}

pub fn compare_sums(split: Script) -> Script {
    script! {
        { split.clone() } OP_TOALTSTACK OP_TOALTSTACK
        { split } OP_FROMALTSTACK OP_FROMALTSTACK
        OP_ROT OP_2DUP OP_NUMEQUAL OP_IF
            OP_2DROP OP_LESSTHAN
        OP_ELSE
            OP_GREATERTHAN OP_NIP OP_NIP
        OP_ENDIF
    }
}
