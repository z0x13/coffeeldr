//! COFF parsing utilities for the CoffeeLdr loader.

use core::ffi::c_void;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use log::{debug, warn};

use crate::error::{CoffError, CoffeeLdrError};

// Architecture definitions for x64
const COFF_MACHINE_X64: u16 = 0x8664;

// Architecture definitions for x32
const COFF_MACHINE_X32: u16 = 0x14c;

/// Limit of sections supported by the Windows loader
const MAX_SECTIONS: u16 = 96;

/// Represents a COFF (Common Object File Format) file.
pub struct Coff<'a> {
    /// The COFF file header (`IMAGE_FILE_HEADER`).
    pub file_header: IMAGE_FILE_HEADER,

    /// A vector of COFF symbols (`IMAGE_SYMBOL`).
    pub symbols: Vec<IMAGE_SYMBOL>,

    /// A vector of section headers (`IMAGE_SECTION_HEADER`).
    pub sections: Vec<IMAGE_SECTION_HEADER>,

    /// The raw contents of the file read into memory
    pub buffer: &'a [u8],

    /// Architecture of the COFF File (x64 or x32)
    pub arch: CoffMachine,
}

impl<'a> Default for Coff<'a> {
    fn default() -> Self {
        Self {
            file_header: IMAGE_FILE_HEADER::default(),
            symbols: Vec::new(),
            sections: Vec::new(),
            buffer: &[],
            arch: CoffMachine::X64,
        }
    }
}

impl<'a> Coff<'a> {
    /// Parses a COFF object from a byte slice.
    ///
    /// The slice must contain a valid COFF file header, section table and
    /// symbol table. Minimal validation is performed to ensure the layout is
    /// consistent.
    ///
    /// # Errors
    ///
    /// Fails when the file is too small, the header is invalid, the
    /// architecture is unsupported, or any section or symbol fails to decode.
    pub fn parse(buffer: &'a [u8]) -> Result<Self, CoffError> {
        debug!("Parsing COFF file header, buffer size: {}", buffer.len());

        // Validates that the file has the minimum size to contain a COFF header
        if buffer.len() < size_of::<IMAGE_FILE_HEADER>() {
            return Err(CoffError::InvalidCoffFile);
        }

        // The COFF file header
        let file_header = IMAGE_FILE_HEADER::from_bytes(buffer)
            .ok_or(CoffError::InvalidCoffFile)?;

        // Detects the architecture of the COFF file and returns an enum `CoffMachine`
        let arch = Self::validate_architecture(file_header)?;

        // Checks that the number of sections and symbols is valid
        let num_sections = file_header.NumberOfSections;
        let num_symbols = file_header.NumberOfSymbols;
        if num_sections == 0 || num_symbols == 0 {
            return Err(CoffError::InvalidSectionsOrSymbols);
        }

        // Validation of the maximum number of sections (Windows limit)
        if num_sections > MAX_SECTIONS {
            warn!("Exceeded maximum number of sections: {} > {}", num_sections, MAX_SECTIONS);
            return Err(CoffError::SectionLimitExceeded);
        }

        // A vector of COFF symbols
        let symbol_offset = file_header.PointerToSymbolTable as usize;
        let symbol_data = buffer.get(symbol_offset..).ok_or(CoffError::InvalidCoffSymbolsFile)?;
        let symbols = (0..num_symbols as usize)
            .map(|i| {
                let offset = i * size_of::<IMAGE_SYMBOL>();
                IMAGE_SYMBOL::from_bytes(symbol_data.get(offset..).ok_or(CoffError::InvalidCoffSymbolsFile)?)
                    .ok_or(CoffError::InvalidCoffSymbolsFile)
            })
            .collect::<Result<Vec<IMAGE_SYMBOL>, _>>()?;

        // A vector of COFF sections
        let section_offset = size_of::<IMAGE_FILE_HEADER>() + file_header.SizeOfOptionalHeader as usize;
        let section_data = buffer.get(section_offset..).ok_or(CoffError::InvalidCoffSectionFile)?;
        let sections = (0..num_sections as usize)
            .map(|i| {
                let offset = i * size_of::<IMAGE_SECTION_HEADER>();
                IMAGE_SECTION_HEADER::from_bytes(section_data.get(offset..).ok_or(CoffError::InvalidCoffSectionFile)?)
                    .ok_or(CoffError::InvalidCoffSectionFile)
            })
            .collect::<Result<Vec<IMAGE_SECTION_HEADER>, _>>()?;

        Ok(Self {
            file_header,
            symbols,
            sections,
            buffer,
            arch,
        })
    }

    /// Determines the machine architecture from the COFF header.
    ///
    /// # Errors
    ///
    /// Fails if the machine field does not match any supported architecture.
    #[inline]
    fn validate_architecture(file_header: IMAGE_FILE_HEADER) -> Result<CoffMachine, CoffError> {
        match file_header.Machine {
            COFF_MACHINE_X64 => Ok(CoffMachine::X64),
            COFF_MACHINE_X32 => Ok(CoffMachine::X32),
            _ => {
                warn!("Unsupported COFF architecture: {:?}", file_header.Machine);
                Err(CoffError::UnsupportedArchitecture)
            }
        }
    }

    /// Computes the total allocation size needed to load the COFF image.
    pub fn size(&self) -> usize {
        let length = self
            .sections
            .iter()
            .filter(|section| section.SizeOfRawData > 0)
            .map(|section| Self::page_align(section.SizeOfRawData as usize))
            .sum();

        let total_length = self
            .sections
            .iter()
            .fold(length, |mut total_length, section| {
                let relocations = self.get_relocations(section);
                relocations.iter().for_each(|relocation| {
                    let Some(sym) = self.symbols.get(relocation.SymbolTableIndex as usize) else {
                        return;
                    };
                    let name = self.get_symbol_name(sym);
                    if name.starts_with("__imp_") {
                        total_length += size_of::<*const c_void>();
                    }
                });

                total_length
            });

        debug!("Total image size after alignment: {} bytes", total_length);
        Self::page_align(total_length)
    }

    /// Returns relocation entries for the specified section.
    ///
    /// Invalid relocations are logged and skipped, allowing parsing to proceed.
    pub fn get_relocations(&self, section: &IMAGE_SECTION_HEADER) -> Vec<IMAGE_RELOCATION> {
        let reloc_offset = section.PointerToRelocations as usize;
        let num_relocs = section.NumberOfRelocations as usize;
        let mut relocations = Vec::with_capacity(num_relocs);

        let Some(reloc_data) = self.buffer.get(reloc_offset..) else {
            return relocations;
        };

        for i in 0..num_relocs {
            let offset = i * size_of::<IMAGE_RELOCATION>();
            match reloc_data.get(offset..).and_then(IMAGE_RELOCATION::from_bytes) {
                Some(reloc) => relocations.push(reloc),
                None => {
                    debug!("Failed to read relocation at index {i}");
                    continue;
                }
            }
        }

        relocations
    }

    /// Reads the symbol name, handling short names and long names from the string table.
    pub fn get_symbol_name(&self, symtbl: &IMAGE_SYMBOL) -> String {
        let name = unsafe {
            if symtbl.N.ShortName[0] != 0 {
                String::from_utf8_lossy(&symtbl.N.ShortName).into_owned()
            } else {
                let long_name_offset = symtbl.N.Name.Long as usize;
                let string_table_offset = self.file_header.PointerToSymbolTable as usize
                    + self.file_header.NumberOfSymbols as usize * size_of::<IMAGE_SYMBOL>();

                let offset = string_table_offset + long_name_offset;
                let Some(name_bytes) = self.buffer.get(offset..) else {
                    return String::new();
                };

                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                String::from_utf8_lossy(&name_bytes[..end]).into_owned()
            }
        };

        name.trim_end_matches('\0').to_string()
    }

    /// Rounds a value up to the next page boundary.
    #[inline]
    pub fn page_align(page: usize) -> usize {
        const SIZE_OF_PAGE: usize = 0x1000;
        (page + SIZE_OF_PAGE - 1) & !(SIZE_OF_PAGE - 1)
    }

    /// Extracts the section name, trimming trailing NUL bytes.
    #[inline]
    pub fn get_section_name(section: &IMAGE_SECTION_HEADER) -> String {
        let s = String::from_utf8_lossy(&section.Name);
        s.trim_end_matches('\0').to_string()
    }

    /// Determines whether a symbol type describes a function.
    #[inline]
    pub fn is_fcn(ty: u16) -> bool {
        (ty & 0x30) == (2 << 4)
    }
}

/// Represents the architecture of the COFF file.
#[derive(Debug, PartialEq, Hash, Clone, Copy, Eq, PartialOrd, Ord)]
pub enum CoffMachine {
    /// 64-bit architecture.
    X64,

    /// 32-bit architecture.
    X32,
}

impl CoffMachine {
    /// Validates that the COFF architecture matches the host process.
    ///
    /// # Errors
    ///
    /// Fails if the COFF architecture does not match the current pointer width.
    #[inline]
    pub fn check_architecture(&self) -> Result<(), CoffeeLdrError> {
        match self {
            CoffMachine::X32 => {
                if cfg!(target_pointer_width = "64") {
                    return Err(CoffeeLdrError::ArchitectureMismatch {
                        expected: "x32",
                        actual: "x64",
                    });
                }
            }
            CoffMachine::X64 => {
                if cfg!(target_pointer_width = "32") {
                    return Err(CoffeeLdrError::ArchitectureMismatch {
                        expected: "x64",
                        actual: "x32",
                    });
                }
            }
        }

        Ok(())
    }
}

/// Represents the COFF data source.
pub enum CoffSource<'a> {
    /// COFF file indicated by a string representing the file path.
    File(&'a str),

    /// Memory buffer containing COFF data.
    Buffer(&'a [u8]),
}

impl<'a> From<&'a str> for CoffSource<'a> {
    fn from(file: &'a str) -> Self {
        CoffSource::File(file)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for CoffSource<'a> {
    fn from(buffer: &'a [u8; N]) -> Self {
        CoffSource::Buffer(buffer)
    }
}

impl<'a> From<&'a [u8]> for CoffSource<'a> {
    fn from(buffer: &'a [u8]) -> Self {
        CoffSource::Buffer(buffer)
    }
}

/// Represents the file header of a COFF (Common Object File Format) file.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    /// The target machine architecture (e.g., x64, x32).
    pub Machine: u16,

    /// The number of sections in the COFF file.
    pub NumberOfSections: u16,

    /// The timestamp when the file was created.
    pub TimeDateStamp: u32,

    /// The pointer to the symbol table.
    pub PointerToSymbolTable: u32,

    /// The number of symbols in the COFF file.
    pub NumberOfSymbols: u32,

    /// The size of the optional header.
    pub SizeOfOptionalHeader: u16,

    /// The characteristics of the file.
    pub Characteristics: u16,
}

impl IMAGE_FILE_HEADER {
    const SIZE: usize = 20;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            Machine: u16::from_le_bytes([bytes[0], bytes[1]]),
            NumberOfSections: u16::from_le_bytes([bytes[2], bytes[3]]),
            TimeDateStamp: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            PointerToSymbolTable: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            NumberOfSymbols: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            SizeOfOptionalHeader: u16::from_le_bytes([bytes[16], bytes[17]]),
            Characteristics: u16::from_le_bytes([bytes[18], bytes[19]]),
        })
    }
}

/// Represents a symbol in the COFF symbol table.
#[derive(Clone, Copy)]
#[repr(C, packed(2))]
pub struct IMAGE_SYMBOL {
    /// The value associated with the symbol.
    pub Value: u32,

    /// The section number that contains the symbol.
    pub SectionNumber: i16,

    /// The type of the symbol.
    pub Type: u16,

    /// The storage class of the symbol (e.g., external, static).
    pub StorageClass: u8,

    /// The number of auxiliary symbol records.
    pub NumberOfAuxSymbols: u8,

    pub N: IMAGE_SYMBOL_0,
}

impl IMAGE_SYMBOL {
    const SIZE: usize = 18;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        let mut name_raw = [0u8; 8];
        name_raw.copy_from_slice(&bytes[0..8]);
        Some(Self {
            Value: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            SectionNumber: i16::from_le_bytes([bytes[12], bytes[13]]),
            Type: u16::from_le_bytes([bytes[14], bytes[15]]),
            StorageClass: bytes[16],
            NumberOfAuxSymbols: bytes[17],
            N: IMAGE_SYMBOL_0 { ShortName: name_raw },
        })
    }
}

/// A union representing different ways a symbol name can be stored.
#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub union IMAGE_SYMBOL_0 {
    /// A short symbol name (8 bytes).
    pub ShortName: [u8; 8],

    /// A long symbol name stored in a different structure.
    pub Name: IMAGE_SYMBOL_0_0,

    /// Long symbol name stored as a pair of u32 values.
    pub LongName: [u32; 2],
}

/// Represents the long name of a symbol as a pair of values.
#[repr(C, packed(2))]
#[derive(Clone, Copy)]
pub struct IMAGE_SYMBOL_0_0 {
    /// The offset to the symbol name.
    pub Short: u32,

    /// The length of the symbol name.
    pub Long: u32,
}

/// Represents a section header in a COFF file.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    /// The name of the section (8 bytes).
    pub Name: [u8; 8],

    /// The virtual address of the section in memory.
    pub VirtualAddress: u32,

    /// The size of the section's raw data.
    pub SizeOfRawData: u32,

    /// The pointer to the raw data in the file.
    pub PointerToRawData: u32,

    /// The pointer to relocation entries.
    pub PointerToRelocations: u32,

    /// The pointer to line numbers (if any).
    pub PointerToLinenumbers: u32,

    /// The number of relocations in the section.
    pub NumberOfRelocations: u16,

    /// The number of line numbers in the section.
    pub NumberOfLinenumbers: u16,

    /// Characteristics that describe the section (e.g., executable, writable).
    pub Characteristics: u32,

    pub Misc: IMAGE_SECTION_HEADER_0,
}

impl IMAGE_SECTION_HEADER {
    const SIZE: usize = 40;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&bytes[0..8]);
        Some(Self {
            Name: name,
            Misc: IMAGE_SECTION_HEADER_0 {
                PhysicalAddress: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            },
            VirtualAddress: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            SizeOfRawData: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            PointerToRawData: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            PointerToRelocations: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            PointerToLinenumbers: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
            NumberOfRelocations: u16::from_le_bytes([bytes[32], bytes[33]]),
            NumberOfLinenumbers: u16::from_le_bytes([bytes[34], bytes[35]]),
            Characteristics: u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]),
        })
    }
}

/// A union representing either the physical or virtual size of the section.
#[repr(C)]
#[derive(Clone, Copy)]
pub union IMAGE_SECTION_HEADER_0 {
    /// The physical address of the section.
    pub PhysicalAddress: u32,

    /// The virtual size of the section.
    pub VirtualSize: u32,
}

/// Represents a relocation entry in a COFF file.
#[repr(C, packed(2))]
pub struct IMAGE_RELOCATION {
    /// The index of the symbol in the symbol table.
    pub SymbolTableIndex: u32,

    /// The type of relocation.
    pub Type: u16,

    pub Anonymous: IMAGE_RELOCATION_0,
}

impl IMAGE_RELOCATION {
    const SIZE: usize = 10;

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            Anonymous: IMAGE_RELOCATION_0 {
                VirtualAddress: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            },
            SymbolTableIndex: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            Type: u16::from_le_bytes([bytes[8], bytes[9]]),
        })
    }
}

/// A union representing either the virtual address or relocation count.
#[repr(C, packed(2))]
pub union IMAGE_RELOCATION_0 {
    /// The virtual address of the relocation.
    pub VirtualAddress: u32,

    /// The relocation count.
    pub RelocCount: u32,
}
