use std::io::{IoSlice, IoSliceMut};

use bstr::ByteSlice;
use nix::{
    sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev},
    unistd::Pid,
};
use region::{Protection, Region};

// Reading from the regions memory directly may cause SIGBUS errors
// See https://www.mail-archive.com/linux-kernel@vger.kernel.org/msg1042714.html
fn try_read_memory(buffer: &mut Vec<u8>, pid: Pid, addr: usize, len: usize) -> Result<(), ()> {
    buffer.resize(len, 0);

    let local_iov = IoSliceMut::new(buffer);
    let remote_iov = RemoteIoVec { base: addr, len };

    match process_vm_readv(pid, &mut [local_iov], &[remote_iov]) {
        Ok(n) if n == len => Ok(()),
        _ => Err(()),
    }
}

unsafe fn try_write_memory(pid: Pid, addr: usize, bytes: &[u8]) -> Result<(), ()> {
    let local_iov = IoSlice::new(bytes);
    let remote_iov = RemoteIoVec {
        base: addr,
        len: bytes.len(),
    };
    match process_vm_writev(pid, &[local_iov], &[remote_iov]) {
        Ok(n) if n == bytes.len() => Ok(()),
        _ => Err(()),
    }
}

pub(crate) struct MemoryScanner {
    pid: Pid,
    regions: Vec<Region>,
}

impl MemoryScanner {
    pub(crate) fn new() -> Self {
        let pid = Pid::this();
        let regions: Vec<_> = region::query_range(std::ptr::null::<()>(), usize::MAX)
            .unwrap()
            .filter_map(|region| region.ok())
            .collect();
        Self { pid, regions }
    }

    pub(crate) fn read_bytes(&self, addr: usize, len: usize) -> Result<Vec<u8>, ()> {
        let mut buffer = vec![];
        try_read_memory(&mut buffer, self.pid, addr, len)?;
        buffer.truncate(len);
        Ok(buffer)
    }

    pub(crate) fn find_bytes(
        &self,
        needle: &[u8],
        mut region_filter: impl FnMut(&Region) -> bool,
    ) -> impl Iterator<Item = (&Region, usize)> {
        gen move {
            let mut buffer = vec![];

            for region in &self.regions {
                if !region_filter(region) {
                    continue;
                }

                let addr = region.as_range().start;
                if try_read_memory(&mut buffer, self.pid, addr, region.len()).is_err() {
                    continue;
                }

                for offset in buffer.find_iter(needle).collect::<Vec<_>>() {
                    yield (region, addr + offset);
                }
            }
        }
    }

    pub(crate) unsafe fn write_bytes(&self, addr: usize, bytes: &[u8]) -> Result<(), ()> {
        let ptr = std::ptr::without_provenance::<()>(addr);
        let regions: Vec<_> = region::query_range(ptr, bytes.len())
            .unwrap()
            .filter_map(|region| region.ok())
            .filter(|region| !region.protection().contains(Protection::WRITE))
            .collect();

        for region in &regions {
            unsafe {
                region::protect(
                    region.as_ptr::<()>(),
                    region.len(),
                    region.protection() | Protection::WRITE,
                )
                .unwrap();
            }
        }

        let _guard = ProtectionGuard { regions };

        unsafe { try_write_memory(self.pid, addr, bytes) }
    }
}

struct ProtectionGuard {
    regions: Vec<Region>,
}

impl Drop for ProtectionGuard {
    fn drop(&mut self) {
        for region in &self.regions {
            unsafe {
                region::protect(region.as_ptr::<()>(), region.len(), region.protection()).unwrap();
            }
        }
    }
}
