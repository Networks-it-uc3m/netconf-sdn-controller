extern crate cmake;
use std::env;
use std::path::PathBuf;
fn main()
{
    let llvm_config_path = "/usr/bin/llvm-config";
    env::set_var("LLVM_CONFIG_PATH", llvm_config_path);
    println!("cargo:rustc-link-search=native=/home/debian/ipsec_tests/ipsec_interactor/libs");
    println!("cargo:rustc-link-lib=static=i2nsf");
    println!("cargo:rustc-link-lib=static=parson");   
    println!("cargo:rustc-link-lib=static=md5"); 
    let bindings = bindgen::Builder::default()
        .header("/home/debian/ipsec_tests/ipsec_interactor/libs/trust_handler.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
