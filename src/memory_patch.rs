use std::ffi::c_void;
use std::path::Path;
use std::ptr;

use bitflags::bitflags;
use minidl;

#[cfg(target_os = "linux")]
use rustix::mm::MprotectFlags;

#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{
    PAGE_EXECUTE, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE,
};

bitflags! {
    /// [MemoryAccess] Represents memory access permissions used when applying patches.
    ///
    /// This includes:
    /// - `NO_ACCESS`          -  No access permissions.
    /// - `READ`               -  Read-only access.
    /// - `WRITE`              -  Write-only access.
    /// - `EXECUTE`            -  Execute-only access.
    /// - `READ_WRITE`         -  Combination of read and write permissions.
    /// - `READ_WRITE_EXECUTE` -  Full read, write, and execute permissions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MemoryAccess: u8 {
        const NO_ACCESS =  0;
        const READ      =  (1 << 0);
        const WRITE     =  (1 << 1);
        const EXECUTE   =  (1 << 2);

        const READ_WRITE = Self::READ.bits() | Self::WRITE.bits();
        const READ_WRITE_EXECUTE = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}

#[cfg(target_os = "linux")]
impl From<MemoryAccess> for MprotectFlags {
    fn from(value: MemoryAccess) -> Self {
        match value {
            MemoryAccess::NO_ACCESS => MprotectFlags::empty(),
            MemoryAccess::READ => MprotectFlags::READ,
            MemoryAccess::WRITE => MprotectFlags::WRITE,
            MemoryAccess::EXECUTE => MprotectFlags::EXEC,
            MemoryAccess::READ_WRITE => MprotectFlags::READ | MprotectFlags::WRITE,
            MemoryAccess::READ_WRITE_EXECUTE => {
                MprotectFlags::READ | MprotectFlags::WRITE | MprotectFlags::EXEC
            }
            _ => panic!(),
        }
    }
}

#[cfg(target_os = "windows")]
impl From<MemoryAccess> for PAGE_PROTECTION_FLAGS {
    fn from(value: MemoryAccess) -> Self {
        match value {
            MemoryAccess::NO_ACCESS => PAGE_NOACCESS,
            MemoryAccess::READ => PAGE_READONLY,
            MemoryAccess::WRITE => PAGE_READWRITE,
            MemoryAccess::EXECUTE => PAGE_EXECUTE,
            MemoryAccess::READ_WRITE => PAGE_READWRITE,
            MemoryAccess::READ_WRITE_EXECUTE => PAGE_EXECUTE_READWRITE,
            _ => panic!(),
        }
    }
}

/// Represents a patch that can be applied to a specific memory region.
///
/// A [MemoryPatch] can apply ( and undo ) a patch at a designated memory address, allowing controlled
/// modification of executable code.
/// The patch does *not* get dropped once it goes out of scope.
#[derive(Debug)]
pub struct MemoryPatch<const N: usize, const T: usize = 0> {
    pub address: *mut c_void,
    original_bytes: Option<[u8; N]>,
    patch: [u8; N],
    verify: Option<[u8; T]>,
}

impl<const N: usize, const T: usize> MemoryPatch<N, T> {
    /// Creates a new [MemoryPatch] instance with specified parameters.
    ///
    /// # Arguments
    /// * `address` - The starting memory address for the patch.
    /// * `patch` - Bytes to apply as the patch.
    /// * `verify` - Optional byte pattern to verify memory contents before patching.
    ///
    /// # Returns
    /// A `Result` containing the [MemoryPatch] struct.
    pub fn new(address: *mut c_void, patch: [u8; N], verify: Option<[u8; T]>) -> Self {
        Self {
            address,
            original_bytes: None,
            patch: patch,
            verify: verify,
        }
    }

    /// Creates a [MemoryPatch] by loading a module and applying an offset.
    ///
    /// # Arguments
    /// * `handle` - Path to the module; loads the current process if `None`.
    /// * `offset` - Offset from the module's base address to the patch location.
    /// * `patch` - Bytes to apply as the patch.
    /// * `verify` - Optional byte pattern to verify memory contents before patching.
    ///
    /// # Returns
    /// A `Result` containing the [MemoryPatch] struct if successful, or an [Error].
    pub fn from_module<P>(
        handle: P,
        offset: usize,
        patch: [u8; N],
        verify: Option<&[u8; T]>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let handle_address = minidl::Library::load(handle)
            .map_err(|err| Error::ModuleLoadingError(err.to_string()))?;

        Ok(Self {
            address: unsafe { handle_address.as_ptr().add(offset) },
            original_bytes: None,
            patch: patch,
            verify: verify.map(|x| *x),
        })
    }

    /// Creates a [MemoryPatch] by referencing a function and applying an offset.
    ///
    /// # Arguments
    /// * `handle` - Path to the module; loads the current process if `None`.
    /// * `function` - Name of the function to base the offset.
    /// * `offset` - Offset from the function’s address to the patch location.
    /// * `patch` - Bytes to apply as the patch.
    /// * `verify` - Optional byte pattern to verify memory contents before patching.
    ///
    /// # Returns
    /// A `Result` containing the [MemoryPatch] struct if successful, or an [Error].
    pub fn from_function<P>(
        handle: P,
        function: &str,
        offset: usize,
        patch: [u8; N],
        verify: Option<&[u8; T]>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let handle_address = minidl::Library::load(handle)
            .map_err(|err| Error::ModuleLoadingError(err.to_string()))?;

        let sym = unsafe {
            handle_address
                .sym::<*mut c_void>(format!("{function}\0"))
                .map_err(|err| Error::FunctionSymbolLoadingError(err.to_string()))?
        };

        Ok(Self {
            address: unsafe { sym.add(offset) },
            original_bytes: None,
            patch: patch,
            verify: verify.map(|x| *x),
        })
    }

    /// Enables the memory patch, saving the original bytes at the address.
    ///
    /// # Returns
    /// A `Result` containing an empty tuple on success, or an [Error].
    pub fn enable(&mut self) -> Result<(), Error> {
        if self.is_enabled() {
            return Ok(());
        }

        self.set_mem_access(MemoryAccess::READ_WRITE_EXECUTE)?;

        let mut test = [0u8; N];

        unsafe {
            ptr::copy(
                self.address as *mut u8,
                test.as_mut_ptr(),
                std::mem::size_of_val(&self.patch),
            )
        }

        unsafe {
            ptr::copy(
                self.patch.as_ptr(),
                self.address as *mut u8,
                std::mem::size_of_val(&self.patch),
            )
        }

        // Should we FlushInstructionCache it?

        /*
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::{
                Diagnostics::Debug::FlushInstructionCache, Threading::GetCurrentProcess,
            };

            unsafe {
                FlushInstructionCache(
                    GetCurrentProcess(),
                    Some(self.address),
                    std::mem::size_of_val(&self.patch),
                )
            };
        }
        */

        self.original_bytes = Some(test);

        Ok(())
    }

    /// Restores the original bytes, disabling the patch.
    ///
    /// # Returns
    /// A `Result` containing an empty tuple on success, or an `io::Error`.
    pub fn disable(&mut self) -> Result<(), Error> {
        let Some(bytes) = self.original_bytes.take() else {
            return Ok(());
        };

        unsafe {
            ptr::copy(
                bytes.as_ptr(),
                self.address as *mut u8,
                std::mem::size_of_val(&bytes),
            )
        };

        // Should we FlushInstructionCache it?

        // We should probably restore the prev state instead.
        self.set_mem_access(MemoryAccess::NO_ACCESS)?;

        Ok(())
    }

    /// Verifies that memory contents match the given verify pattern.
    ///
    /// # Returns
    /// A `Result` containing an empty tuple on success, or an [Error].
    pub fn verify(&self) -> Result<bool, Error> {
        let Some(verify) = self.verify else {
            return Ok(true);
        };

        self.set_mem_access(MemoryAccess::READ)?;

        let memory_region = unsafe {
            std::slice::from_raw_parts(self.address as *mut u8, std::mem::size_of_val(&verify))
        };

        // If this happens, for any reason, in the middle of an enabled patch,
        // I'm kind of undoing the previous memory access,
        // which will result in a crash.
        self.set_mem_access(MemoryAccess::NO_ACCESS)?;

        let is_matching = memory_region == verify.as_slice();

        Ok(is_matching)
    }

    /// Sets memory access rights at the target address.
    ///
    /// # Arguments
    /// * `access` - Desired memory access rights ( [MemoryAccess] ).
    ///
    /// # Returns
    /// A `Result` containing an empty tuple on success, or an `io::Error`.
    fn set_mem_access(&self, access: MemoryAccess) -> Result<(), Error> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Memory::VirtualProtect;

            let mut old_protect = PAGE_PROTECTION_FLAGS(0);

            unsafe {
                VirtualProtect(
                    self.address,
                    std::mem::size_of_val(&self.patch),
                    access.into(),
                    &mut old_protect,
                )
                .map_err(|err| Error::MemoryAccessError(err.to_string()))
            }
        }

        #[cfg(target_os = "linux")]
        {
            use rustix::mm::mprotect;

            unsafe {
                mprotect(
                    self.address,
                    std::mem::size_of_val(&self.patch),
                    access.into(),
                )
                .map_err(|err| Error::MemoryAccessError(err.to_string()))
            }
        }
    }

    /// Checks if the [MemoryPatch] is enabled.
    ///
    /// # Returns
    /// `true` if the patch is enabled, otherwise `false`.
    fn is_enabled(&self) -> bool {
        self.original_bytes.is_some()
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("error while loading a module: {0}")]
    ModuleLoadingError(String),

    #[error("error while trying to find a symbol: {0}")]
    FunctionSymbolLoadingError(String),

    #[error("error while setting the memory protection access: {0}")]
    MemoryAccessError(String),
}
