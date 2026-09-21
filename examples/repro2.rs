use pack_chain_microscope::git::read_size_varint;
fn main() {
    let h = [176u8, 250, 1]; // blob size 4000
    let first = h[0];
    let code = (first >> 3) & 0x07;
    println!("code={code}");
    println!("size={:?}", read_size_varint(&h[1..], first));
}
