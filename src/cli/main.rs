use pe::data_source::FileDataSource;
use pe::PeFile;



fn main() {
    let self_path = std::env::current_exe().unwrap();
    let result = FileDataSource::open_file(&self_path);
    match result {
        Ok(file_data) => {
            let pe = PeFile::parse(file_data).unwrap();
            println!("{:#?}",pe.get_nt_headers());
        }
        Err(e) => {
            println!("{}", e);
        }
    }
}
