use clap::{Parser, ValueEnum};
use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table};
use pe::PeFile;
use pe::report::Report;
use pe::pe_structs_wrapper::ImportEntry;
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
    ///
    /// If omitted, the executable's own path is used (i.e. `peviewer-rs`
    /// parses itself).
    #[arg(value_name = "PATH|ADDR|PID|URL")]
    input: Option<String>,

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

    /// Print the export directory. (coming soon)
    #[arg(long)]
    exports: bool,

    /// Print the import directory.
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

    // Resolve the input target.  If the user did not pass one, default to
    // the running executable so a bare `peviewer-rs` invocation inspects
    // itself — useful for quick smoke tests.
    let input_display: String = match &cli.input {
        Some(s) => s.clone(),
        None => match std::env::current_exe() {
            Ok(p) => p.display().to_string(),
            Err(e) => {
                eprintln!("error: no input given and could not resolve current exe: {e}");
                process::exit(1);
            }
        },
    };

    let pe_file = match open_source(&cli.source, cli.input.as_deref()) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!(
                "error: could not open '{input_display}' (source = {:?}): {e}",
                cli.source
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
        print_report(pe_file.dos_header_report());
    }

    if want(cli.nt) {
        print_report(pe_file.file_header_report());
        print_report(pe_file.optional_header_report());
    }

    if want(cli.sections) {
        print_report(pe_file.sections_report());
    }

    if want(cli.imports) {
        print_imports(&pe_file);
    }

    if cli.exports {
        eprintln!("note: --exports is coming soon; not yet implemented");
    }

    // Directories that are not wired up yet. They are only reported when
    // requested explicitly; `--all` skips them to stay quiet.
    for (requested, name) in [
        (cli.data_directories, "data-directories"),
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

/// Open a [`PeFile`] from the selected data source.  When `input` is
/// `None`, the running executable's path is used.
fn open_source(source: &Source, input: Option<&str>) -> Result<PeFile, String> {
    match source {
        Source::File => {
            let path = match input {
                Some(s) => PathBuf::from(s),
                None => std::env::current_exe().map_err(|e| e.to_string())?,
            };
            PeFile::open_from_file(&path).map_err(|e| e.to_string())
        }
        Source::Memory => Err("memory data source is not yet implemented".into()),
        Source::Process => Err("process data source is not yet implemented".into()),
        Source::Url => Err("url data source is not yet implemented".into()),
    }
}

/// Render any [`Report`] as a table, printed under a `=== <title> ===`
/// heading.
fn print_report(report: Report) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(report.headers);

    for row in report.rows {
        table.add_row(row);
    }

    println!("=== {} ===", report.title);
    println!("{table}");
}


/// Print the import table: one block per imported DLL, with the
/// per-function entry kind (by-name or by-ordinal).
fn print_imports(pe_file: &PeFile) {
    let imports = pe_file.imports();
    println!("=== Imports ===");
    if imports.is_empty() {
        println!("(none)");
        return;
    }

    for imp in imports {
        let entries = imp.import_name_table();
        println!("  [{}]  ({} functions)", imp.dll_name(), entries.len());
        for entry in entries {
            match entry {
                ImportEntry::ImportByName(_hint, name) => println!("    {name}"),
                ImportEntry::ImportByOrdinal(ord) => println!("    (ord {ord})"),
                ImportEntry::FunctionAddress(addr) => println!("    <{addr:#018x}>"),
            }
        }
    }
}
