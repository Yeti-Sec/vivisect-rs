//! vivbin - Vivisect command-line binary analysis tool.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vivisect::core::VivWorkspace;
use vivisect::error::VivResult;
use vivisect::parsers::{detect_format, BinaryFormat};

/// Vivisect binary analysis framework.
#[derive(Parser)]
#[command(name = "vivbin")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Binary file to analyze.
    #[arg(global = true)]
    file: Option<PathBuf>,

    /// Verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a binary file.
    Analyze {
        /// Binary file to analyze.
        file: PathBuf,

        /// Output workspace file.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show information about a binary.
    Info {
        /// Binary file to inspect.
        file: PathBuf,
    },

    /// List functions in a binary.
    Functions {
        /// Binary or workspace file.
        file: PathBuf,
    },

    /// List imports in a binary.
    Imports {
        /// Binary file.
        file: PathBuf,
    },

    /// List exports in a binary.
    Exports {
        /// Binary file.
        file: PathBuf,
    },

    /// List sections in a binary.
    Sections {
        /// Binary file.
        file: PathBuf,
    },

    /// Disassemble at an address.
    Disasm {
        /// Binary file.
        file: PathBuf,

        /// Start address (hex).
        #[arg(short, long)]
        address: Option<String>,

        /// Number of instructions.
        #[arg(short, long, default_value = "20")]
        count: usize,
    },
}

fn main() -> VivResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Analyze { file, output }) => {
            cmd_analyze(&file, output.as_deref(), cli.verbose)?;
        }
        Some(Commands::Info { file }) => {
            cmd_info(&file)?;
        }
        Some(Commands::Functions { file }) => {
            cmd_functions(&file)?;
        }
        Some(Commands::Imports { file }) => {
            cmd_imports(&file)?;
        }
        Some(Commands::Exports { file }) => {
            cmd_exports(&file)?;
        }
        Some(Commands::Sections { file }) => {
            cmd_sections(&file)?;
        }
        Some(Commands::Disasm { file, address, count }) => {
            cmd_disasm(&file, address.as_deref(), count)?;
        }
        None => {
            if let Some(file) = cli.file {
                cmd_info(&file)?;
            } else {
                println!("Vivisect {} - Binary Analysis Framework", vivisect::VERSION);
                println!();
                println!("Usage: vivbin <COMMAND> [OPTIONS] <FILE>");
                println!();
                println!("Commands:");
                println!("  analyze   Analyze a binary file");
                println!("  info      Show information about a binary");
                println!("  functions List functions");
                println!("  imports   List imports");
                println!("  exports   List exports");
                println!("  sections  List sections");
                println!("  disasm    Disassemble at address");
                println!();
                println!("Use 'vivbin --help' for more information.");
            }
        }
    }

    Ok(())
}

fn cmd_analyze(file: &PathBuf, _output: Option<&std::path::Path>, verbose: bool) -> VivResult<()> {
    if verbose {
        println!("Analyzing: {}", file.display());
    }

    let mut workspace = VivWorkspace::new();
    workspace.load_from_file(file)?;

    let stats = workspace.stats();
    println!("Analysis complete:");
    println!("  Architecture: {:?}", workspace.architecture());
    println!("  Segments:     {}", stats.segments);
    println!("  Symbols:      {}", stats.symbols);
    println!("  Memory:       {} bytes", stats.memory_size);

    if !workspace.entry_points().is_empty() {
        println!("  Entry points:");
        for entry in workspace.entry_points() {
            println!("    {:#x}", entry);
        }
    }

    Ok(())
}

fn cmd_info(file: &PathBuf) -> VivResult<()> {
    println!("File: {}", file.display());

    let format = detect_format(file)?;
    println!("Format: {:?}", format);

    match format {
        BinaryFormat::Pe => {
            let pe = vivisect::parsers::PeParser::load(file)?;
            println!("Architecture: {:?}", pe.architecture());
            println!("Image Base:   {:#x}", pe.image_base());
            println!("Entry Point:  {:#x}", pe.entry_point());
            println!("Is 64-bit:    {}", pe.is_64());
            println!("Is DLL:       {}", pe.is_dll());
            println!("Sections:     {}", pe.sections().len());
            println!("Imports:      {}", pe.imports().len());
            println!("Exports:      {}", pe.exports().len());
        }
        BinaryFormat::Elf => {
            let elf = vivisect::parsers::ElfParser::load(file)?;
            println!("Architecture: {:?}", elf.architecture());
            println!("Entry Point:  {:#x}", elf.entry_point());
            println!("Is 64-bit:    {}", elf.is_64());
            println!("Sections:     {}", elf.sections().len());
            println!("Imports:      {}", elf.imports().len());
            println!("Exports:      {}", elf.exports().len());
        }
        _ => {
            println!("Unknown or unsupported format");
        }
    }

    Ok(())
}

fn cmd_functions(file: &PathBuf) -> VivResult<()> {
    let mut workspace = VivWorkspace::new();
    workspace.load_from_file(file)?;

    let functions = workspace.get_functions();
    if functions.is_empty() {
        println!("No functions found (run analysis first)");
    } else {
        println!("Functions ({}):", functions.len());
        for addr in functions {
            let name = workspace.get_name(addr).unwrap_or("<unnamed>");
            println!("  {:#x}  {}", addr, name);
        }
    }

    Ok(())
}

fn cmd_imports(file: &PathBuf) -> VivResult<()> {
    let format = detect_format(file)?;

    match format {
        BinaryFormat::Pe => {
            let pe = vivisect::parsers::PeParser::load(file)?;
            let imports = pe.imports();
            println!("Imports ({}):", imports.len());
            for imp in imports {
                if imp.library.is_empty() {
                    println!("  {:#x}  {}", imp.address, imp.name);
                } else {
                    println!("  {:#x}  {}!{}", imp.address, imp.library, imp.name);
                }
            }
        }
        BinaryFormat::Elf => {
            let elf = vivisect::parsers::ElfParser::load(file)?;
            let imports = elf.imports();
            println!("Imports ({}):", imports.len());
            for imp in imports {
                println!("  {:#x}  {}", imp.address, imp.name);
            }
        }
        _ => {
            println!("Format does not support imports");
        }
    }

    Ok(())
}

fn cmd_exports(file: &PathBuf) -> VivResult<()> {
    let format = detect_format(file)?;

    match format {
        BinaryFormat::Pe => {
            let pe = vivisect::parsers::PeParser::load(file)?;
            let exports = pe.exports();
            println!("Exports ({}):", exports.len());
            for exp in exports {
                println!("  {:#x}  {}", exp.address, exp.name);
            }
        }
        BinaryFormat::Elf => {
            let elf = vivisect::parsers::ElfParser::load(file)?;
            let exports = elf.exports();
            println!("Exports ({}):", exports.len());
            for exp in exports {
                println!("  {:#x}  {}", exp.address, exp.name);
            }
        }
        _ => {
            println!("Format does not support exports");
        }
    }

    Ok(())
}

fn cmd_sections(file: &PathBuf) -> VivResult<()> {
    let format = detect_format(file)?;

    match format {
        BinaryFormat::Pe => {
            let pe = vivisect::parsers::PeParser::load(file)?;
            let sections = pe.sections();
            println!("Sections ({}):", sections.len());
            println!("{:<16} {:>16} {:>12} {:>8}", "Name", "VirtualAddr", "VirtualSize", "Perms");
            println!("{}", "-".repeat(56));
            for s in sections {
                let perms = format!(
                    "{}{}{}",
                    if s.readable { "r" } else { "-" },
                    if s.writable { "w" } else { "-" },
                    if s.executable { "x" } else { "-" }
                );
                println!("{:<16} {:#16x} {:>12} {:>8}", s.name, s.virtual_address, s.virtual_size, perms);
            }
        }
        BinaryFormat::Elf => {
            let elf = vivisect::parsers::ElfParser::load(file)?;
            let sections = elf.sections();
            println!("Sections ({}):", sections.len());
            println!("{:<20} {:>16} {:>12} {:>8}", "Name", "VirtualAddr", "Size", "Perms");
            println!("{}", "-".repeat(60));
            for s in sections {
                let perms = format!(
                    "{}{}{}",
                    if s.readable { "r" } else { "-" },
                    if s.writable { "w" } else { "-" },
                    if s.executable { "x" } else { "-" }
                );
                println!("{:<20} {:#16x} {:>12} {:>8}", s.name, s.virtual_address, s.virtual_size, perms);
            }
        }
        _ => {
            println!("Format does not have sections");
        }
    }

    Ok(())
}

fn cmd_disasm(file: &PathBuf, address: Option<&str>, count: usize) -> VivResult<()> {
    use vivisect::constants::Architecture;
    use vivisect::envi::archs::{X86Disassembler, X86Mode};

    let mut workspace = VivWorkspace::new();
    workspace.load_from_file(file)?;

    let start_addr = if let Some(addr_str) = address {
        let addr_str = addr_str.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(addr_str, 16).map_err(|_| vivisect::VivError::Other {
            message: format!("Invalid address: {}", addr_str),
        })?
    } else {
        workspace.entry_points().first().copied().unwrap_or(0)
    };

    // Create appropriate disassembler
    let disasm = match workspace.architecture() {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => {
            return Err(vivisect::VivError::Other {
                message: format!("Unsupported architecture: {:?}", workspace.architecture()),
            });
        }
    };

    println!("Disassembly at {:#x}:", start_addr);
    println!("{:<16} {:<24} {}", "Address", "Bytes", "Instruction");
    println!("{}", "-".repeat(60));

    let mut current_addr = start_addr;
    let mut instructions = 0;

    while instructions < count {
        // Read bytes at current address
        let bytes = match workspace.read_memory(current_addr, 16) {
            Ok(b) => b,
            Err(_) => {
                println!("{:#016x}: <invalid memory>", current_addr);
                break;
            }
        };

        // Disassemble instruction
        match disasm.disassemble(&bytes, current_addr) {
            Ok(op) => {
                let bytes_hex: String = bytes[..op.size as usize]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");

                // Format operands
                let operands: Vec<String> = (0..op.operand_count())
                    .filter_map(|i| op.get_operand(i).map(|o| format!("{:?}", o)))
                    .collect();
                let operand_str = if operands.is_empty() {
                    String::new()
                } else {
                    format!(" {}", operands.join(", "))
                };

                println!(
                    "{:#016x}: {:<24} {}{}",
                    current_addr,
                    bytes_hex,
                    op.mnem,
                    operand_str
                );

                current_addr += op.size as u64;
                instructions += 1;

                // Stop at return instructions
                if op.is_return() {
                    break;
                }
            }
            Err(_) => {
                println!("{:#016x}: <invalid instruction>", current_addr);
                break;
            }
        }
    }

    Ok(())
}
