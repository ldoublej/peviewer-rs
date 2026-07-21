use pe::data_source::FileDataSource;
use pe::PeFile;



fn main() {
    let self_path = std::env::current_exe().unwrap();
    let result_of_opening = FileDataSource::open_file(&self_path);
    match result_of_opening {
        Ok(file_data) => {
            let pe = PeFile::parse(&file_data).unwrap();
            let _dos_magic = pe.dos_magic();
            println!("Hello, world!");
        }
        Err(e) => {
            println!("{}", e);
        }
    }
}
