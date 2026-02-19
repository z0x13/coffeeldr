use alloc::string::String;
use const_encrypt::obf;
use core::fmt;

pub type Result<T> = core::result::Result<T, CoffeeLdrError>;

#[derive(Debug)]
pub enum CoffeeLdrError {
    Msg(String),
    Hex(hex::FromHexError),
    CoffError(CoffError),
    MemoryAllocationError(u32),
    MemoryProtectionError(u32),
    InvalidSymbolFormat(String),
    InvalidRelocationType(u16),
    FunctionNotFound(String),
    FunctionInternalNotFound(String),
    ModuleNotFound(String),
    ParsingError,
    ArchitectureMismatch { expected: u8, actual: u8 },
    TooManySymbols(usize),
    ParseError(String),
    SymbolIgnored,
    OutputError,
    StompingTextSectionNotFound,
    StompingSizeOverflow,
    MissingStompingBaseAddress,
}

impl fmt::Display for CoffeeLdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Msg(s) => f.write_str(s),
            Self::Hex(err) => write!(f, "{err}"),
            Self::CoffError(err) => write!(f, "{err}"),
            Self::MemoryAllocationError(code) => {
                write!(f, "{}: {code}", obf!("memory allocation error"))
            }
            Self::MemoryProtectionError(code) => {
                write!(f, "{}: {code}", obf!("memory protection error"))
            }
            Self::InvalidSymbolFormat(s) => write!(f, "{}: {s}", obf!("invalid symbol format")),
            Self::InvalidRelocationType(t) => {
                write!(f, "{}: {t}", obf!("invalid relocation type"))
            }
            Self::FunctionNotFound(s) => write!(f, "{}: {s}", obf!("function not found")),
            Self::FunctionInternalNotFound(s) => {
                write!(f, "{}: {s}", obf!("internal function not found"))
            }
            Self::ModuleNotFound(s) => write!(f, "{}: {s}", obf!("module not found")),
            Self::ParsingError => write!(f, "{}", obf!("parsing error")),
            Self::ArchitectureMismatch { expected, actual } => {
                write!(f, "{}: x{expected} / x{actual}", obf!("arch mismatch"))
            }
            Self::TooManySymbols(n) => write!(f, "{}: {n}", obf!("too many symbols")),
            Self::ParseError(s) => write!(f, "{}: {s}", obf!("parse error")),
            Self::SymbolIgnored => write!(f, "{}", obf!("symbol ignored")),
            Self::OutputError => write!(f, "{}", obf!("output error")),
            Self::StompingTextSectionNotFound => {
                write!(f, "{}", obf!("text section not found"))
            }
            Self::StompingSizeOverflow => write!(f, "{}", obf!("stomping size overflow")),
            Self::MissingStompingBaseAddress => write!(f, "{}", obf!("missing base address")),
        }
    }
}

impl core::error::Error for CoffeeLdrError {}

#[derive(Debug)]
pub enum CoffError {
    FileReadError(String),
    InvalidCoffFile,
    InvalidCoffSymbolsFile,
    InvalidCoffSectionFile,
    UnsupportedArchitecture,
    InvalidSectionsOrSymbols,
    SectionLimitExceeded,
}

impl fmt::Display for CoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileReadError(s) => write!(f, "{}: {s}", obf!("file read error")),
            Self::InvalidCoffFile => write!(f, "{}", obf!("invalid file")),
            Self::InvalidCoffSymbolsFile => write!(f, "{}", obf!("invalid symbols")),
            Self::InvalidCoffSectionFile => write!(f, "{}", obf!("invalid sections")),
            Self::UnsupportedArchitecture => write!(f, "{}", obf!("unsupported architecture")),
            Self::InvalidSectionsOrSymbols => {
                write!(f, "{}", obf!("invalid sections or symbols"))
            }
            Self::SectionLimitExceeded => write!(f, "{}", obf!("section limit exceeded")),
        }
    }
}

impl core::error::Error for CoffError {}

impl From<CoffError> for CoffeeLdrError {
    fn from(err: CoffError) -> Self {
        CoffeeLdrError::CoffError(err)
    }
}

impl From<hex::FromHexError> for CoffeeLdrError {
    fn from(err: hex::FromHexError) -> Self {
        CoffeeLdrError::Hex(err)
    }
}
