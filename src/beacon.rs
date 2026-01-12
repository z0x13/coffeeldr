use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    alloc::Layout,
    ffi::{CStr, c_void},
    ffi::{c_char, c_int, c_short},
    fmt,
    ptr::{self, null_mut},
};

use spin::Mutex;
use obfstr::obfstr as s;
use dinvk::{winapis::NtCurrentProcess, syscall};
use dinvk::types::OBJECT_ATTRIBUTES;
use windows_sys::Win32::{
    Security::*,
    Foundation::{CloseHandle, DuplicateHandle, HANDLE, STATUS_SUCCESS},
    System::{
        Threading::*,
        WindowsProgramming::CLIENT_ID,
        Diagnostics::Debug::{
            GetThreadContext,
            SetThreadContext,
            ReadProcessMemory,
            WriteProcessMemory,
            CONTEXT,
        },
        Memory::{
            MEM_COMMIT,
            MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
            MEMORY_BASIC_INFORMATION,
            MEMORY_MAPPED_VIEW_ADDRESS,
            VirtualAlloc,
            VirtualAllocEx,
            VirtualProtect,
            VirtualProtectEx,
            VirtualFree,
            VirtualQuery,
            UnmapViewOfFile,
        },
    },
};

use const_hashes::murmur3;
use crate::error::{CoffeeLdrError, Result};

/// Global output buffer used by Beacon-compatible functions.
static BEACON_BUFFER: Mutex<BeaconOutputBuffer> = Mutex::new(BeaconOutputBuffer::new());

/// Global key-value store for BOF inter-call data sharing.
static BEACON_KV_STORE: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());

/// Maximum number of data store entries.
pub const DATA_STORE_MAX_ENTRIES: usize = 16;

/// Data store type constants.
pub const DATA_STORE_TYPE_EMPTY: i32 = 0;
#[allow(dead_code)]
pub const DATA_STORE_TYPE_GENERAL_FILE: i32 = 1;

/// Data store object structure matching Cobalt Strike's DATA_STORE_OBJECT.
#[repr(C)]
pub struct DataStoreObject {
    pub obj_type: i32,
    pub hash: u64,
    pub masked: i32,
    pub buffer: *mut c_char,
    pub length: usize,
}

impl DataStoreObject {
    const fn empty() -> Self {
        Self {
            obj_type: DATA_STORE_TYPE_EMPTY,
            hash: 0,
            masked: 0,
            buffer: null_mut(),
            length: 0,
        }
    }
}

// SAFETY: DataStoreObject is protected by a Mutex and only accessed through controlled APIs.
unsafe impl Send for DataStoreObject {}
unsafe impl Sync for DataStoreObject {}

/// Global data store for BOF file/data sharing.
static BEACON_DATA_STORE: Mutex<[DataStoreObject; DATA_STORE_MAX_ENTRIES]> = Mutex::new([const { DataStoreObject::empty() }; DATA_STORE_MAX_ENTRIES]);

/// A buffer used for managing and collecting output for the beacon.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BeaconOutputBuffer {
    /// Internal buffer that stores the output data as a vector of `c_char`.
    pub buffer: Vec<c_char>,
}

impl BeaconOutputBuffer {
    /// Creates a new empty output buffer.
    const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Appends raw C-style bytes to the internal buffer.
    ///
    /// Invalid pointers or negative lengths are ignored.
    fn append_char(&mut self, s: *mut c_char, len: c_int) {
        if s.is_null() || len <= 0 {
            return;
        }
        let tmp = unsafe { core::slice::from_raw_parts(s, len as usize) };
        self.buffer.extend_from_slice(tmp);
    }

    /// Appends plain Rust text to the buffer.
    fn append_string(&mut self, s: &str) {
        self.buffer.extend(s.bytes().map(|b| b as c_char));
    }

    /// Returns the current buffer pointer and size, and clears the buffer.
    ///
    /// This behaves exactly like the Beacon BOF runtime.
    fn get_output(&mut self) -> (*mut c_char, usize) {
        let size = self.buffer.len();
        let ptr = self.buffer.as_mut_ptr();
        self.buffer.clear();
        (ptr, size)
    }

    /// Clears all output data stored in the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl fmt::Display for BeaconOutputBuffer {
    /// Converts the internal buffer into a Rust `String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = self
            .buffer
            .iter()
            .map(|&c| if c as u8 == 0 { '\n' } else { c as u8 as char })
            .collect::<String>();
        write!(f, "{string}")
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Data {
    /// The original buffer.
    original: *mut c_char,

    /// Current pointer into our buffer.
    buffer: *mut c_char,

    /// Remaining length of data.
    length: c_int,

    /// Total size of this buffer.
    size: c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Format {
    /// The original buffer.
    original: *mut c_char,

    /// Current pointer into our buffer.
    buffer: *mut c_char,

    /// Remaining length of data.
    length: c_int,

    /// Total size of this buffer.
    size: c_int,
}

// Beacon function hash constants (murmur3)
const H_BEACON_PRINTF: u32 = murmur3!("BeaconPrintf");
const H_BEACON_OUTPUT: u32 = murmur3!("BeaconOutput");
const H_BEACON_GET_OUTPUT_DATA: u32 = murmur3!("BeaconGetOutputData");
const H_BEACON_IS_ADMIN: u32 = murmur3!("BeaconIsAdmin");
const H_BEACON_USE_TOKEN: u32 = murmur3!("BeaconUseToken");
const H_BEACON_REVERT_TOKEN: u32 = murmur3!("BeaconRevertToken");
const H_BEACON_FORMAT_INT: u32 = murmur3!("BeaconFormatInt");
const H_BEACON_FORMAT_FREE: u32 = murmur3!("BeaconFormatFree");
const H_BEACON_FORMAT_ALLOC: u32 = murmur3!("BeaconFormatAlloc");
const H_BEACON_FORMAT_RESET: u32 = murmur3!("BeaconFormatReset");
const H_BEACON_FORMAT_PRINTF: u32 = murmur3!("BeaconFormatPrintf");
const H_BEACON_FORMAT_APPEND: u32 = murmur3!("BeaconFormatAppend");
const H_BEACON_FORMAT_TO_STRING: u32 = murmur3!("BeaconFormatToString");
const H_BEACON_GET_SPAWN_TO: u32 = murmur3!("BeaconGetSpawnTo");
const H_BEACON_INJECT_PROCESS: u32 = murmur3!("BeaconInjectProcess");
const H_BEACON_CLEANUP_PROCESS: u32 = murmur3!("BeaconCleanupProcess");
const H_BEACON_SPAWN_TEMPORARY_PROCESS: u32 = murmur3!("BeaconSpawnTemporaryProcess");
const H_BEACON_INJECT_TEMPORARY_PROCESS: u32 = murmur3!("BeaconInjectTemporaryProcess");
const H_BEACON_DATA_INT: u32 = murmur3!("BeaconDataInt");
const H_BEACON_DATA_SHORT: u32 = murmur3!("BeaconDataShort");
const H_BEACON_DATA_PARSE: u32 = murmur3!("BeaconDataParse");
const H_BEACON_DATA_LENGTH: u32 = murmur3!("BeaconDataLength");
const H_BEACON_DATA_EXTRACT: u32 = murmur3!("BeaconDataExtract");
const H_BEACON_DATA_PTR: u32 = murmur3!("BeaconDataPtr");
const H_TO_WIDE_CHAR: u32 = murmur3!("toWideChar");
const H_BEACON_INFORMATION: u32 = murmur3!("BeaconInformation");
const H_BEACON_ADD_VALUE: u32 = murmur3!("BeaconAddValue");
const H_BEACON_GET_VALUE: u32 = murmur3!("BeaconGetValue");
const H_BEACON_REMOVE_VALUE: u32 = murmur3!("BeaconRemoveValue");
const H_BEACON_VIRTUAL_ALLOC: u32 = murmur3!("BeaconVirtualAlloc");
const H_BEACON_VIRTUAL_ALLOC_EX: u32 = murmur3!("BeaconVirtualAllocEx");
const H_BEACON_VIRTUAL_PROTECT: u32 = murmur3!("BeaconVirtualProtect");
const H_BEACON_VIRTUAL_PROTECT_EX: u32 = murmur3!("BeaconVirtualProtectEx");
const H_BEACON_VIRTUAL_FREE: u32 = murmur3!("BeaconVirtualFree");
const H_BEACON_VIRTUAL_QUERY: u32 = murmur3!("BeaconVirtualQuery");
const H_BEACON_GET_THREAD_CONTEXT: u32 = murmur3!("BeaconGetThreadContext");
const H_BEACON_SET_THREAD_CONTEXT: u32 = murmur3!("BeaconSetThreadContext");
const H_BEACON_RESUME_THREAD: u32 = murmur3!("BeaconResumeThread");
const H_BEACON_OPEN_PROCESS: u32 = murmur3!("BeaconOpenProcess");
const H_BEACON_OPEN_THREAD: u32 = murmur3!("BeaconOpenThread");
const H_BEACON_CLOSE_HANDLE: u32 = murmur3!("BeaconCloseHandle");
const H_BEACON_UNMAP_VIEW_OF_FILE: u32 = murmur3!("BeaconUnmapViewOfFile");
const H_BEACON_DUPLICATE_HANDLE: u32 = murmur3!("BeaconDuplicateHandle");
const H_BEACON_READ_PROCESS_MEMORY: u32 = murmur3!("BeaconReadProcessMemory");
const H_BEACON_WRITE_PROCESS_MEMORY: u32 = murmur3!("BeaconWriteProcessMemory");
const H_BEACON_DATA_STORE_GET_ITEM: u32 = murmur3!("BeaconDataStoreGetItem");
const H_BEACON_DATA_STORE_PROTECT_ITEM: u32 = murmur3!("BeaconDataStoreProtectItem");
const H_BEACON_DATA_STORE_UNPROTECT_ITEM: u32 = murmur3!("BeaconDataStoreUnprotectItem");
const H_BEACON_DATA_STORE_MAX_ENTRIES: u32 = murmur3!("BeaconDataStoreMaxEntries");

/// Resolves the internal address of a built-in Beacon function.
///
/// The lookup uses a murmur3 hash of the symbol name to match the
/// internal function used by BOF payloads.
///
/// # Errors
///
/// Fails when the requested function is not mapped to any known internal handler.
pub fn get_function_internal_address(name: &str) -> Result<usize> {
    match const_hashes::runtime::murmur3(name) {
        // Output
        H_BEACON_PRINTF => Ok(beacon_printf as *const () as usize),
        H_BEACON_OUTPUT => Ok(beacon_output as *const () as usize),
        H_BEACON_GET_OUTPUT_DATA => Ok(beacon_get_output_data as *const () as usize),

        // Token
        H_BEACON_IS_ADMIN => Ok(beacon_is_admin as *const () as usize),
        H_BEACON_USE_TOKEN => Ok(beacon_use_token as *const () as usize),
        H_BEACON_REVERT_TOKEN => Ok(beacon_rever_token as *const () as usize),

        // Format
        H_BEACON_FORMAT_INT => Ok(beacon_format_int as *const () as usize),
        H_BEACON_FORMAT_FREE => Ok(beacon_format_free as *const () as usize),
        H_BEACON_FORMAT_ALLOC => Ok(beacon_format_alloc as *const () as usize),
        H_BEACON_FORMAT_RESET => Ok(beacon_format_reset as *const () as usize),
        H_BEACON_FORMAT_PRINTF => Ok(beacon_formt_printf as *const () as usize),
        H_BEACON_FORMAT_APPEND => Ok(beacon_format_append as *const () as usize),
        H_BEACON_FORMAT_TO_STRING => Ok(beacon_format_to_string as *const () as usize),

        // Process / injection
        H_BEACON_GET_SPAWN_TO => Ok(beacon_get_spawn_to as *const () as usize),
        H_BEACON_INJECT_PROCESS => Ok(beacon_inject_process as *const () as usize),
        H_BEACON_CLEANUP_PROCESS => Ok(beacon_cleanup_process as *const () as usize),
        H_BEACON_SPAWN_TEMPORARY_PROCESS => Ok(beacon_spawn_temporary_process as *const () as usize),
        H_BEACON_INJECT_TEMPORARY_PROCESS => Ok(beacon_inject_temporary_process as *const () as usize),

        // Data
        H_BEACON_DATA_INT => Ok(beacon_data_int as *const () as usize),
        H_BEACON_DATA_SHORT => Ok(beacon_data_short as *const () as usize),
        H_BEACON_DATA_PARSE => Ok(beacon_data_parse as *const () as usize),
        H_BEACON_DATA_LENGTH => Ok(beacon_data_length as *const () as usize),
        H_BEACON_DATA_EXTRACT => Ok(beacon_data_extract as *const () as usize),
        H_BEACON_DATA_PTR => Ok(beacon_data_ptr as *const () as usize),

        // Utils
        H_TO_WIDE_CHAR => Ok(to_wide_char as *const () as usize),
        H_BEACON_INFORMATION => Ok(0),

        // Key-Value Store
        H_BEACON_ADD_VALUE => Ok(beacon_add_value as *const () as usize),
        H_BEACON_GET_VALUE => Ok(beacon_get_value as *const () as usize),
        H_BEACON_REMOVE_VALUE => Ok(beacon_remove_value as *const () as usize),

        // Alloc wrappers
        H_BEACON_VIRTUAL_ALLOC => Ok(beacon_virtual_alloc as *const () as usize),
        H_BEACON_VIRTUAL_ALLOC_EX => Ok(beacon_virtual_alloc_ex as *const () as usize),
        H_BEACON_VIRTUAL_PROTECT => Ok(beacon_virtual_protect as *const () as usize),
        H_BEACON_VIRTUAL_PROTECT_EX => Ok(beacon_virtual_protect_ex as *const () as usize),
        H_BEACON_VIRTUAL_FREE => Ok(beacon_virtual_free as *const () as usize),
        H_BEACON_VIRTUAL_QUERY => Ok(beacon_virtual_query as *const () as usize),

        // Thread/process/handle wrappers
        H_BEACON_GET_THREAD_CONTEXT => Ok(beacon_get_thread_context as *const () as usize),
        H_BEACON_SET_THREAD_CONTEXT => Ok(beacon_set_thread_context as *const () as usize),
        H_BEACON_RESUME_THREAD => Ok(beacon_resume_thread as *const () as usize),
        H_BEACON_OPEN_PROCESS => Ok(beacon_open_process as *const () as usize),
        H_BEACON_OPEN_THREAD => Ok(beacon_open_thread as *const () as usize),
        H_BEACON_CLOSE_HANDLE => Ok(beacon_close_handle as *const () as usize),
        H_BEACON_UNMAP_VIEW_OF_FILE => Ok(beacon_unmap_view_of_file as *const () as usize),
        H_BEACON_DUPLICATE_HANDLE => Ok(beacon_duplicate_handle as *const () as usize),
        H_BEACON_READ_PROCESS_MEMORY => Ok(beacon_read_process_memory as *const () as usize),
        H_BEACON_WRITE_PROCESS_MEMORY => Ok(beacon_write_process_memory as *const () as usize),

        // Data Store
        H_BEACON_DATA_STORE_GET_ITEM => Ok(beacon_data_store_get_item as *const () as usize),
        H_BEACON_DATA_STORE_PROTECT_ITEM => Ok(beacon_data_store_protect_item as *const () as usize),
        H_BEACON_DATA_STORE_UNPROTECT_ITEM => Ok(beacon_data_store_unprotect_item as *const () as usize),
        H_BEACON_DATA_STORE_MAX_ENTRIES => Ok(beacon_data_store_max_entries as *const () as usize),

        _ => Err(CoffeeLdrError::FunctionInternalNotFound(name.to_string())),
    }
}

/// Retrieves the current Beacon output buffer.
///
/// If no output has been produced, returns `None`.
/// Otherwise returns a cloned snapshot and clears the internal buffer.
pub fn get_output_data() -> Option<BeaconOutputBuffer> {
    let mut beacon = BEACON_BUFFER.lock();
    if beacon.buffer.is_empty() {
        return None;
    }

    let output = beacon.clone();
    beacon.clear();

    Some(output)
}

/// Allocates a new `Format` buffer for Beacon-formatting operations.
///
/// Allocation uses zeroed memory and behaves like the standard BOF runtime.
fn beacon_format_alloc(format: *mut Format, max: c_int) {
    if format.is_null() || max == 0 {
        return;
    }

    let layout_result = Layout::from_size_align(max as usize, Layout::new::<i8>().align());
    if let Ok(layout) = layout_result {
        unsafe {
            let original = alloc::alloc::alloc_zeroed(layout).cast::<i8>();
            (*format).original = original;
            (*format).buffer = original;
            (*format).length = 0;
            (*format).size = max;
        }
    }
}

/// Clears the contents of a `Format` buffer by zeroing it.
///
/// The pointer is reset back to the beginning.
fn beacon_format_reset(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        ptr::write_bytes((*format).original, 0, (*format).size as usize);
        (*format).buffer = (*format).original;
        (*format).length = (*format).size;
    }
}

/// Converts the contents of a `Format` buffer into a C-style string.
///
/// Returns a pointer to the underlying buffer.
fn beacon_format_to_string(format: *mut Format, size: *mut c_int) -> *mut c_char {
    if format.is_null() || size.is_null() {
        return null_mut();
    }

    unsafe {
        (*size) = (*format).length;
        (*format).original
    }
}

/// Appends a big-endian integer to the format buffer.
fn beacon_format_int(format: *mut Format, value: c_int) {
    if format.is_null() {
        return;
    }

    unsafe {
        if (*format).length + 4 > (*format).size {
            return;
        }

        let outdata = swap_endianness(value as u32).to_be_bytes();
        ptr::copy_nonoverlapping(outdata.as_ptr(), (*format).buffer as *mut u8, 4);

        (*format).buffer = (*format).buffer.add(4);
        (*format).length += 4;
    }
}

/// Appends arbitrary raw bytes to a `Format` buffer.
fn beacon_format_append(format: *mut Format, text: *const c_char, len: c_int) {
    if format.is_null() || text.is_null() || len <= 0 {
        return;
    }

    unsafe {
        if (*format).length + len > (*format).size {
            return;
        }

        ptr::copy_nonoverlapping(text, (*format).buffer, len as usize);
        (*format).buffer = (*format).buffer.add(len as usize);
        (*format).length += len;
    }
}

/// Frees the memory associated with a `Format` buffer.
fn beacon_format_free(format: *mut Format) {
    if format.is_null() {
        return;
    }

    unsafe {
        if !(*format).original.is_null() {
            let layout_result = Layout::from_size_align((*format).size as usize, Layout::new::<i8>().align());
            if let Ok(layout) = layout_result {
                alloc::alloc::dealloc((*format).original as *mut u8, layout);
                (*format).original = null_mut();
            }
        }

        (*format).buffer = null_mut();
        (*format).length = 0;
        (*format).size = 0;
    }
}

/// Formats a string using printf-style formatting and appends the result
/// to a `Format` buffer.
///
/// Follows the behavior of Beacon’s `beacon_formt_printf`.
#[unsafe(no_mangle)]
unsafe extern "C" fn beacon_formt_printf(format: *mut Format, fmt: *const c_char, args: ...) {
    if format.is_null() || fmt.is_null() {
        return;
    }

    let fmt_str = CStr::from_ptr(fmt).to_str().unwrap_or("");
    let mut temp_str = String::new();

    printf_compat::format(fmt_str.as_ptr().cast(), args, printf_compat::output::fmt_write(&mut temp_str));

    let length_needed = temp_str.len() as c_int;
    if (*format).length + length_needed >= (*format).size {
        return;
    }

    ptr::copy_nonoverlapping(
        temp_str.as_ptr() as *const c_char,
        (*format).buffer.add((*format).length as usize),
        length_needed as usize,
    );

    (*format).length += length_needed;
}

/// Extracts a 2-byte value from a Beacon `Data` buffer.
fn beacon_data_short(data: *mut Data) -> c_short {
    if data.is_null() {
        return 0;
    }

    let parser = unsafe { &mut *data };
    if parser.length < 2 {
        return 0;
    }

    let result = unsafe { ptr::read_unaligned(parser.buffer as *const i16) };
    parser.buffer = unsafe { parser.buffer.add(2) };
    parser.length -= 2;

    result as c_short
}

/// Extracts a 4-byte value from a Beacon `Data` buffer.
fn beacon_data_int(data: *mut Data) -> c_int {
    if data.is_null() {
        return 0;
    }

    let parser = unsafe { &mut *data };
    if parser.length < 4 {
        return 0;
    }

    let result = unsafe { ptr::read_unaligned(parser.buffer as *const i32) };
    parser.buffer = unsafe { parser.buffer.add(4) };
    parser.length -= 4;

    result as c_int
}

/// Extracts an arbitrary-length blob from a `Data` buffer.
fn beacon_data_extract(data: *mut Data, size: *mut c_int) -> *mut c_char {
    if data.is_null() {
        return null_mut();
    }

    let parser = unsafe { &mut *data };
    if parser.length < 4 {
        return null_mut();
    }

    let length = unsafe { ptr::read_unaligned(parser.buffer as *const u32) };
    let outdata = unsafe { parser.buffer.add(4) };
    if outdata.is_null() {
        return null_mut();
    }

    parser.buffer = unsafe { parser.buffer.add(4 + length as usize) };
    parser.length -= 4 + length as c_int;
    if !size.is_null() && !outdata.is_null() {
        unsafe {
            *size = length as c_int;
        }
    }

    outdata as *mut c_char
}

/// Initializes a `Data` parser over a raw buffer.
fn beacon_data_parse(data: *mut Data, buffer: *mut c_char, size: c_int) {
    if data.is_null() {
        return;
    }

    unsafe {
        (*data).original = buffer;
        (*data).buffer = buffer.add(4);
        (*data).length = size - 4;
        (*data).size = size - 4;
    }
}

/// Returns the remaining data length in a `Data` parser.
fn beacon_data_length(data: *const Data) -> c_int {
    if data.is_null() {
        return 0;
    }

    unsafe { (*data).length }
}

/// Returns the collected Beacon output and size as raw bytes.
fn beacon_get_output_data(outsize: *mut c_int) -> *mut c_char {
    unsafe {
        let mut beacon = BEACON_BUFFER.lock();
        let (ptr, size) = beacon.get_output();

        if !outsize.is_null() {
            *outsize = size as c_int;
        }

        ptr
    }
}

/// Appends raw output data into the Beacon output buffer.
fn beacon_output(_type: c_int, data: *mut c_char, len: c_int) {
    let mut buffer = BEACON_BUFFER.lock();
    buffer.append_char(data, len);
}

/// Formats a string using Beacon’s printf mechanism and stores it.
#[unsafe(no_mangle)]
unsafe extern "C" fn beacon_printf(_type: c_int, fmt: *mut c_char, args: ...) {
    let mut str = String::new();
    printf_compat::format(fmt, args, printf_compat::output::fmt_write(&mut str));
    str.push('\0');

    let mut buffer = BEACON_BUFFER.lock();
    buffer.append_string(&str);
}

/// Reverts any impersonated token back to the original process token.
fn beacon_rever_token() {
    unsafe {
        if RevertToSelf() == 0 {
            log::warn!("RevertToSelf Failed!")
        }
    }
}

/// Applies a token to the current thread.
fn beacon_use_token(token: HANDLE) -> i32 {
    unsafe { SetThreadToken(null_mut(), token) }
}

/// Closes handles associated with a spawned process.
fn beacon_cleanup_process(info: *const PROCESS_INFORMATION) {
    unsafe {
        CloseHandle((*info).hProcess);
        CloseHandle((*info).hThread);
    }
}

/// Checks whether the current process is elevated (admin token).
fn beacon_is_admin() -> u32 {
    let mut h_token = null_mut();

    unsafe {
        if OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &mut h_token) != 0 {
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length = 0;

            if GetTokenInformation(
                h_token,
                TokenElevation,
                &mut elevation as *mut _ as *mut c_void,
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            ) != 0
            {
                return (elevation.TokenIsElevated == 1) as u32;
            }
        }
    }

    0
}

/// Converts endianness of a 32-bit integer.
fn swap_endianness(src: u32) -> u32 {
    // Check if the system is little-endian
    if cfg!(target_endian = "little") {
        // Small-endian to large-endian converter
        src.swap_bytes()
    } else {
        // If it is already big-endian, it returns the original value
        src
    }
}

/// Converts a C-string to UTF-16 and writes it into the destination buffer.
fn to_wide_char(src: *const c_char, dst: *mut u16, max: c_int) -> c_int {
    if src.is_null() || dst.is_null() || max < size_of::<u16>() as c_int {
        return 0;
    }

    unsafe {
        // Converting the `src` pointer to a C string
        let c_str = CStr::from_ptr(src);

        // Converts CStr to a Rust string
        if let Ok(str_slice) = c_str.to_str() {
            // Encoding a Rust string as UTF-16
            let utf16_chars = str_slice.encode_utf16().collect::<Vec<u16>>();
            let dst_slice = core::slice::from_raw_parts_mut(dst, (max as usize) / size_of::<u16>());

            let num_chars = utf16_chars.len();
            if num_chars >= dst_slice.len() {
                return 0; // Not enough space
            }

            // Copy the UTF-16 characters to the destination buffer
            dst_slice[..num_chars].copy_from_slice(&utf16_chars);

            // Adds the null-terminator
            dst_slice[num_chars] = 0;
        }
    }

    1
}

/// Performs remote process injection into a target process via NT syscalls.
fn beacon_inject_process(
    _h_process: HANDLE, 
    pid: c_int, 
    payload: *const c_char, 
    len: c_int, 
    _offset: c_char, 
    _arg: *const c_char, 
    _a_len: c_int
) {
    if payload.is_null() || len <= 0 {
        return;
    }

    unsafe {
        let mut oa = OBJECT_ATTRIBUTES::default();
        let mut ci = CLIENT_ID {
            UniqueProcess: pid as HANDLE,
            UniqueThread: null_mut(),
        };

        let mut h_process = null_mut::<c_void>();
        let status = syscall!(s!("NtOpenProcess"), &mut h_process, PROCESS_ALL_ACCESS, &mut oa, &mut ci);
        if status != Some(STATUS_SUCCESS) {
            return;
        }

        let mut size = len as usize;
        let mut address = null_mut::<c_void>();
        let mut status = syscall!(
            s!("NtAllocateVirtualMemory"),
            h_process,
            &mut address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if status != Some(STATUS_SUCCESS) {
            CloseHandle(h_process);
            return;
        }

        let mut now = 0usize;
        status = syscall!(s!("NtWriteVirtualMemory"), h_process, address, payload as *const c_void, len as usize, &mut now);
        if status != Some(STATUS_SUCCESS) {
            CloseHandle(h_process);
            return;
        }

        let mut h_thread = null_mut::<c_void>();
        status = syscall!(
            s!("NtCreateThreadEx"),
            &mut h_thread,
            THREAD_ALL_ACCESS,
            null_mut::<c_void>(),
            h_process,
            address,
            null_mut::<c_void>(),
            0usize,
            0usize,
            0usize,
            0usize,
            null_mut::<c_void>()
        );

        if status != Some(STATUS_SUCCESS) || h_thread.is_null() {
            CloseHandle(h_process);
            return;
        }

        CloseHandle(h_thread);
        CloseHandle(h_process);
    }
}

/// Extracts a pointer to a region of the `Data` buffer.
fn beacon_data_ptr(data: *mut Data, size: c_int) -> *mut c_char {
    if data.is_null() || size <= 0 {
        return null_mut();
    }

    let parser = unsafe { &mut *data };
    if parser.length < size {
        return null_mut();
    }

    let result = parser.buffer;
    parser.buffer = unsafe { parser.buffer.add(size as usize) };
    parser.length -= size;

    result
}

/// Leaving this to be implemented by people needing/wanting it
fn beacon_inject_temporary_process(
    _info: *const PROCESS_INFORMATION,
    _payload: *const c_char,
    _len: c_int,
    _offset: c_int,
    _arg: *const c_char,
    _a_len: c_int,
) {
    unimplemented!()
}

/// Leaving this to be implemented by people needing/wanting it
fn beacon_spawn_temporary_process(
    _x86: i32, 
    _ignore_token: i32, 
    _s_info: *mut STARTUPINFOA, 
    _p_info: *mut PROCESS_INFORMATION
) {
    unimplemented!()
}

/// Leaving this to be implemented by people needing/wanting it
fn beacon_get_spawn_to(_x86: i32, _buffer: *const c_char, _length: c_int) {
    unimplemented!()
}

/// Adds a key-value pair to the global store.
/// Returns TRUE if added successfully, FALSE if key already exists or ptr is NULL.
fn beacon_add_value(key: *const c_char, ptr: *mut c_void) -> i32 {
    if key.is_null() || ptr.is_null() {
        return 0;
    }

    let key_str = unsafe {
        match CStr::from_ptr(key).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    let mut store = BEACON_KV_STORE.lock();
    if store.contains_key(key_str) {
        return 0;
    }

    store.insert(key_str.into(), ptr as usize);
    1
}

/// Retrieves a value from the global store by key.
/// Returns NULL if key not found.
fn beacon_get_value(key: *const c_char) -> *mut c_void {
    if key.is_null() {
        return null_mut();
    }

    let key_str = unsafe {
        match CStr::from_ptr(key).to_str() {
            Ok(s) => s,
            Err(_) => return null_mut(),
        }
    };

    let store = BEACON_KV_STORE.lock();
    store.get(key_str).map_or(null_mut(), |&v| v as *mut c_void)
}

/// Removes a key-value pair from the global store.
/// Returns TRUE if removed, FALSE if key not found.
fn beacon_remove_value(key: *const c_char) -> i32 {
    if key.is_null() {
        return 0;
    }

    let key_str = unsafe {
        match CStr::from_ptr(key).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    let mut store = BEACON_KV_STORE.lock();
    if store.remove(key_str).is_some() { 1 } else { 0 }
}

/// Allocates virtual memory in the current process.
/// Proxy to kernel32!VirtualAlloc.
fn beacon_virtual_alloc(
    address: *mut c_void,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> *mut c_void {
    unsafe { VirtualAlloc(address, size, alloc_type, protect) }
}

/// Allocates virtual memory in the specified process.
/// Proxy to kernel32!VirtualAllocEx.
fn beacon_virtual_alloc_ex(
    process: HANDLE,
    address: *mut c_void,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> *mut c_void {
    unsafe { VirtualAllocEx(process, address, size, alloc_type, protect) }
}

/// Changes protection on a region of virtual memory in the current process.
/// Proxy to kernel32!VirtualProtect.
fn beacon_virtual_protect(
    address: *mut c_void,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    unsafe { VirtualProtect(address, size, new_protect, old_protect) }
}

/// Changes protection on a region of virtual memory in the specified process.
/// Proxy to kernel32!VirtualProtectEx.
fn beacon_virtual_protect_ex(
    process: HANDLE,
    address: *mut c_void,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    unsafe { VirtualProtectEx(process, address, size, new_protect, old_protect) }
}

/// Releases or decommits virtual memory in the current process.
/// Proxy to kernel32!VirtualFree.
fn beacon_virtual_free(address: *mut c_void, size: usize, free_type: u32) -> i32 {
    unsafe { VirtualFree(address, size, free_type) }
}

/// Queries information about a region of virtual memory.
/// Proxy to kernel32!VirtualQuery.
fn beacon_virtual_query(
    address: *const c_void,
    buffer: *mut MEMORY_BASIC_INFORMATION,
    length: usize,
) -> usize {
    unsafe { VirtualQuery(address, buffer, length) }
}

/// Gets the context of the specified thread.
/// Proxy to kernel32!GetThreadContext.
fn beacon_get_thread_context(thread: HANDLE, context: *mut CONTEXT) -> i32 {
    unsafe { GetThreadContext(thread, context) }
}

/// Sets the context of the specified thread.
/// Proxy to kernel32!SetThreadContext.
fn beacon_set_thread_context(thread: HANDLE, context: *const CONTEXT) -> i32 {
    unsafe { SetThreadContext(thread, context) }
}

/// Resumes the specified thread.
/// Proxy to kernel32!ResumeThread.
fn beacon_resume_thread(thread: HANDLE) -> u32 {
    unsafe { ResumeThread(thread) }
}

/// Opens an existing process object.
/// Proxy to kernel32!OpenProcess.
fn beacon_open_process(desired_access: u32, inherit_handle: i32, process_id: u32) -> HANDLE {
    unsafe { OpenProcess(desired_access, inherit_handle, process_id) }
}

/// Opens an existing thread object.
/// Proxy to kernel32!OpenThread.
fn beacon_open_thread(desired_access: u32, inherit_handle: i32, thread_id: u32) -> HANDLE {
    unsafe { OpenThread(desired_access, inherit_handle, thread_id) }
}

/// Closes an open object handle.
/// Proxy to kernel32!CloseHandle.
fn beacon_close_handle(handle: HANDLE) -> i32 {
    unsafe { CloseHandle(handle) }
}

/// Unmaps a mapped view of a file from the calling process's address space.
/// Proxy to kernel32!UnmapViewOfFile.
fn beacon_unmap_view_of_file(base_address: *const c_void) -> i32 {
    let addr = MEMORY_MAPPED_VIEW_ADDRESS { Value: base_address as *mut c_void };
    unsafe { UnmapViewOfFile(addr) }
}

/// Duplicates an object handle.
/// Proxy to kernel32!DuplicateHandle.
fn beacon_duplicate_handle(
    source_process: HANDLE,
    source_handle: HANDLE,
    target_process: HANDLE,
    target_handle: *mut HANDLE,
    desired_access: u32,
    inherit_handle: i32,
    options: u32,
) -> i32 {
    unsafe {
        DuplicateHandle(
            source_process,
            source_handle,
            target_process,
            target_handle,
            desired_access,
            inherit_handle,
            options,
        )
    }
}

/// Reads data from an area of memory in a specified process.
/// Proxy to kernel32!ReadProcessMemory.
fn beacon_read_process_memory(
    process: HANDLE,
    base_address: *const c_void,
    buffer: *mut c_void,
    size: usize,
    bytes_read: *mut usize,
) -> i32 {
    unsafe { ReadProcessMemory(process, base_address, buffer, size, bytes_read) }
}

/// Writes data to an area of memory in a specified process.
/// Proxy to kernel32!WriteProcessMemory.
fn beacon_write_process_memory(
    process: HANDLE,
    base_address: *mut c_void,
    buffer: *const c_void,
    size: usize,
    bytes_written: *mut usize,
) -> i32 {
    unsafe { WriteProcessMemory(process, base_address, buffer, size, bytes_written) }
}

/// Returns a pointer to the DataStoreObject at the specified index.
/// Returns NULL if index is out of bounds or entry is empty.
fn beacon_data_store_get_item(index: usize) -> *mut DataStoreObject {
    if index >= DATA_STORE_MAX_ENTRIES {
        return null_mut();
    }

    let store = BEACON_DATA_STORE.lock();
    let item = &store[index];

    if item.obj_type == DATA_STORE_TYPE_EMPTY {
        return null_mut();
    }

    item as *const DataStoreObject as *mut DataStoreObject
}

/// XOR masks the buffer of the DataStoreObject at the specified index.
fn beacon_data_store_protect_item(index: usize) {
    if index >= DATA_STORE_MAX_ENTRIES {
        return;
    }

    let mut store = BEACON_DATA_STORE.lock();
    let item = &mut store[index];

    if item.obj_type == DATA_STORE_TYPE_EMPTY || item.buffer.is_null() || item.masked != 0 {
        return;
    }

    let key_bytes = item.hash.to_le_bytes();
    let buffer = unsafe { core::slice::from_raw_parts_mut(item.buffer as *mut u8, item.length) };

    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte ^= key_bytes[i % 8];
    }

    item.masked = 1;
}

/// Unmasks the buffer of the DataStoreObject at the specified index.
fn beacon_data_store_unprotect_item(index: usize) {
    if index >= DATA_STORE_MAX_ENTRIES {
        return;
    }

    let mut store = BEACON_DATA_STORE.lock();
    let item = &mut store[index];

    if item.obj_type == DATA_STORE_TYPE_EMPTY || item.buffer.is_null() || item.masked == 0 {
        return;
    }

    let key_bytes = item.hash.to_le_bytes();
    let buffer = unsafe { core::slice::from_raw_parts_mut(item.buffer as *mut u8, item.length) };

    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte ^= key_bytes[i % 8];
    }

    item.masked = 0;
}

/// Returns the maximum number of data store entries.
fn beacon_data_store_max_entries() -> usize {
    DATA_STORE_MAX_ENTRIES
}
