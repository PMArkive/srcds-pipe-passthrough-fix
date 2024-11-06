#![feature(generic_arg_infer)]

use retour_utils::*;
use std::env;
use std::ffi::CString;
use std::mem;
use std::os::raw::c_char;
use std::ptr;
use windows::core::PCSTR;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

pub mod memory_patch;

#[allow(non_camel_case_types)]
type DedicatedMain_t = extern "C" fn(
    h_instance: HMODULE,
    _h_prev_instance: HMODULE,
    lp_cmd_line: *const c_char,
    n_cmd_show: i32,
) -> i32;

#[cfg(target_arch = "x86")]
const ALLOC_CONSOLE_PATCH: [u8; 4] = [
    0x33, 0xc0, // XOR EAX, EAX
    0x40, // INC EAX
    0xc3, // RET
];

#[cfg(target_arch = "x86_64")]
const ALLOC_CONSOLE_PATCH: [u8; 7] = [
    0x48, 0x31, 0xc0, // XOR RAX, RAX
    0x48, 0xff, 0xc0, // INC RAX
    0xc3, // RET
];

fn main() {
    let _ = unsafe { kernel32::init_detours() };

    let mut patch = memory_patch::MemoryPatch::<_>::from_function(
        "kernel32.dll",
        "AllocConsole",
        0,
        ALLOC_CONSOLE_PATCH,
        None,
    )
    .unwrap();

    patch.enable().unwrap();

    let instace = unsafe { GetModuleHandleA(None).unwrap() };
    let prev_instance = HMODULE(ptr::null_mut());
    let args = CString::new(env::args().collect::<Vec<String>>().join(" ")).unwrap();

    let path = env::var("PATH").unwrap();

    let executable_path = env::current_exe().unwrap();

    #[cfg(target_arch = "x86")]
    let new_path = format!(
        "{}\\bin;{}",
        executable_path.parent().unwrap().to_str().unwrap(),
        path
    );

    #[cfg(target_arch = "x86_64")]
    let new_path = format!(
        "{}\\bin\\x64;{}",
        executable_path.parent().unwrap().to_str().unwrap(),
        path
    );

    env::set_var("PATH", &new_path);

    let launcher =
        unsafe { LoadLibraryA(PCSTR::from_raw("dedicated.dll\0".as_ptr() as *const u8)) }.unwrap();

    if launcher.is_invalid() {
        return;
    }

    let dedicated_main: DedicatedMain_t =
        unsafe { mem::transmute(GetProcAddress(launcher, PCSTR("DedicatedMain\0".as_ptr()))) };

    dedicated_main(instace, prev_instance, args.as_ptr(), 0);
}

#[hook_module("kernel32.dll")]
mod kernel32 {
    use std::ptr;

    use windows::Win32::Storage::FileSystem::ReadFile;
    use windows::Win32::{
        Foundation::{BOOL, HANDLE},
        System::Console::{
            INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
        },
    };

    // We don't actually need it. It seems that there is a bug in retour-utils,
    // which makes it so that, when compiling for i686-windows-msvc, the first
    // hook is "non-existent", for whatever reason.
    // This is basically just a dummy detour that does nothing.
    #[hook(unsafe extern "system" AllocConsoleHook, symbol = "AllocConsole")]
    fn alloc_console() -> BOOL {
        unsafe { AllocConsoleHook.call() }
    }

    #[hook(unsafe extern "system" GetNumberOfConsoleInputEvents, symbol = "GetNumberOfConsoleInputEvents")]
    fn get_number_of_console_input_events(
        _hconsoleinput: HANDLE,
        _lpc_number_of_events: *mut u32,
    ) -> BOOL {
        // DO NOT REMOVE THE GLOBAL VARIABLE.
        // The only reason it works is because of it.
        // Weirdest workaround ever.
        static mut GLOBAL_BOOL: bool = true;

        unsafe {
            ptr::write(_lpc_number_of_events, GLOBAL_BOOL as u32);

            GLOBAL_BOOL = !GLOBAL_BOOL;
        }

        BOOL(1)
    }

    #[hook(unsafe extern "system" ReadConsoleInputAHook, symbol = "ReadConsoleInputA")]
    fn read_console_input(
        hconsoleinput: HANDLE,
        lpbuffer: *mut INPUT_RECORD,
        length: u32,
        lpnumberofeventsread: *mut u32,
    ) -> BOOL {
        let mut buf: [u8; 1024] = [0; 1024];
        let mut bytes_read = 0u32;

        unsafe { ptr::write(lpnumberofeventsread, 0) };

        let _ = unsafe { ReadFile(hconsoleinput, Some(&mut buf), Some(&mut bytes_read), None) };

        if bytes_read == 0 {
            return BOOL(1);
        }

        let mut events_written = 0;
        for i in 0..bytes_read as usize {
            let byte = buf[i];

            let key_event = KEY_EVENT_RECORD {
                bKeyDown: BOOL(1),
                wRepeatCount: 1,
                wVirtualKeyCode: byte.to_ascii_uppercase() as u16,
                wVirtualScanCode: byte as u16,
                uChar: KEY_EVENT_RECORD_0 {
                    AsciiChar: byte as i8,
                },
                dwControlKeyState: if byte.is_ascii_uppercase() { 0x80 } else { 0x0 },
            };

            let input_record = INPUT_RECORD {
                EventType: KEY_EVENT as u16,
                Event: INPUT_RECORD_0 {
                    KeyEvent: key_event,
                },
            };

            unsafe {
                *lpbuffer.add(events_written) = input_record;
            }

            events_written += 1;

            if events_written >= length as usize {
                break;
            }
        }

        let key_event = KEY_EVENT_RECORD {
            bKeyDown: BOOL(1),
            wRepeatCount: 1,
            wVirtualKeyCode: b'\r'.to_ascii_uppercase() as u16,
            wVirtualScanCode: b'\r' as u16,
            uChar: KEY_EVENT_RECORD_0 {
                AsciiChar: b'\r' as i8,
            },
            dwControlKeyState: if b'\r'.is_ascii_uppercase() {
                0x80
            } else {
                0x0
            },
        };

        let input_record = INPUT_RECORD {
            EventType: KEY_EVENT as u16,
            Event: INPUT_RECORD_0 {
                KeyEvent: key_event,
            },
        };

        unsafe {
            *lpbuffer.add(events_written) = input_record;
        }

        events_written += 1;

        unsafe {
            *lpnumberofeventsread = events_written as u32;
        }

        BOOL(1)
    }
}
