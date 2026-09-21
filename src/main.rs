use pack_chain_microscope::git;

fn main() {
    let oid = git::git_object_id("blob", b"hello");
    println!("{}", git::oid_hex(&oid));
}
