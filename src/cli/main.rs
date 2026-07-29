use clap::{Parser, ValueEnum};
use pe::PeFile;
use std::path::PathBuf;
use std::process;

/// Inspect the structure of a PE (Portable Executable) image.
///
/// Select a data source with `--source`, point it at a target, and choose
/// which parts of the PE structure to print. Parts that are not implemented
/// yet are accepted as flags but report "not yet implemented" so the planned
/// command-line surface is stable.
#[derive(Parser)]
#[command(
    name = "peviewer-rs",
    version,
    about = "Inspect the structure of a PE (Portable Executable) image"
)]
struct Cli {
    /// Where the PE image is read from.
    #[arg(short, long, value_enum, value_name = "SOURCE", default_value_t = Source::File)]
    source: Source,

    /// Target for the data source: a file path (`file`), a memory address
    /// (`memory`), a process PID (`process`), or a URL (`url`).
    #[arg(value_name = "PATH|ADDR|PID|URL")]
    input: String,

    // ---- Content selection ------------------------------------------------
    /// Print the DOS header.
    #[arg(long)]
    dos: bool,

    /// Print the NT headers (signature, file header, optional header).
    #[arg(long)]
    nt: bool,

    /// Print the section table.
    #[arg(long)]
    sections: bool,

    /// Print the data directory table. (not yet implemented)
    #[arg(long)]
    data_directories: bool,

    /// Print the export directory. (not yet implemented)
    #[arg(long)]
    exports: bool,

    /// Print the import directory. (not yet implemented)
    #[arg(long)]
    imports: bool,

    /// Print the resource directory. (not yet implemented)
    #[arg(long)]
    resources: bool,

    /// Print the exception directory. (not yet implemented)
    #[arg(long)]
    exceptions: bool,

    /// Print the security / certificate directory. (not yet implemented)
    #[arg(long)]
    security: bool,

    /// Print the base relocation table. (not yet implemented)
    #[arg(long)]
    relocations: bool,

    /// Print the debug directory. (not yet implemented)
    #[arg(long)]
    debug: bool,

    /// Print the TLS directory. (not yet implemented)
    #[arg(long)]
    tls: bool,

    /// Print the load config directory. (not yet implemented)
    #[arg(long)]
    load_config: bool,

    /// Print all available content. Unimplemented directories are skipped.
    #[arg(long)]
    all: bool,
}

/// Selectable data source for a PE image.
#[derive(Clone, Debug, ValueEnum)]
enum Source {
    /// Read from a file on disk.
    File,
    /// Read from a mapped memory address. (not yet implemented)
    Memory,
    /// Read from a running process by PID. (not yet implemented)
    Process,
    /// Download and read from a URL. (not yet implemented)
    Url,
}

fn main() {
    let cli = Cli::parse();

    let pe_file = match open_source(&cli.source, &cli.input) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!(
                "error: could not open '{}' (source = {:?}): {e}",
                cli.input, cli.source
            );
            process::exit(1);
        }
    };

    // If nothing was explicitly requested, fall back to the implemented
    // content so `peviewer-rs <file>` is useful out of the box. Explicitly
    // selecting any item suppresses that default.
    let any_selected = cli.all
        || cli.dos
        || cli.nt
        || cli.sections
        || cli.data_directories
        || cli.exports
        || cli.imports
        || cli.resources
        || cli.exceptions
        || cli.security
        || cli.relocations
        || cli.debug
        || cli.tls
        || cli.load_config;
    let want = |flag: bool| cli.all || flag || !any_selected;

    // Implemented content.
    if want(cli.dos) {
        println!("=== DOS Header ===");
        println!("{:#?}", pe_file.dos_header());
    }
    
    if want(cli.nt) {
        println!("=== NT Headers ===");
        println!("{:#?}", pe_file.nt_headers());
    }
    
    if want(cli.sections) {
        println!("=== Sections ===");
        println!("{:#?}", pe_file.sections());
    }

    // Directories that are not wired up yet. They are only reported when
    // requested explicitly; `--all` skips them to stay quiet.
    for (requested, name) in [
        (cli.data_directories, "data-directories"),
        (cli.exports, "exports"),
        (cli.imports, "imports"),
        (cli.resources, "resources"),
        (cli.exceptions, "exceptions"),
        (cli.security, "security"),
        (cli.relocations, "relocations"),
        (cli.debug, "debug"),
        (cli.tls, "tls"),
        (cli.load_config, "load-config"),
    ] {
        if requested {
            eprintln!("note: --{name} is not yet implemented");
        }
    }
}

/// Open a [`PeFile`] from the selected data source.
fn open_source(source: &Source, input: &str) -> Result<PeFile, String> {
    match source {
        Source::File => {
            let path = PathBuf::from(input);
            PeFile::open_from_file(&path).map_err(|e| e.to_string())
        }
        Source::Memory => Err("memory data source is not yet implemented".into()),
        Source::Process => Err("process data source is not yet implemented".into()),
        Source::Url => Err("url data source is not yet implemented".into()),
    }
}
