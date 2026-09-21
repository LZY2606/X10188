use pack_chain_microscope as lib;

fn main() {
    println!("init {}", lib::gitid::oid_hex(&lib::gitid::git_object_id(
        lib::gitid::ObjType::Blob,
        b"init",
    )));
}
