use pe::PeFile;

fn main() {
    let self_path = std::env::current_exe().unwrap();
    let pe_file = PeFile::open_from_file(&self_path).unwrap();
    println!("{:#?}", pe_file.dos_header());
    println!("{:#?}", pe_file.nt_headers());
    println!("{:#?}", pe_file.sections());
}
