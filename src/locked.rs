//! Fixed-size secrets (keys) in memory that is locked into RAM.
//!
//! Each [`Locked`] value gets **its own page-aligned allocation**, so locking and unlocking one
//! never affects another (`munlock` works on whole pages). On Unix the pages are `mlock`ed (not
//! written to swap) and, on Linux, marked `MADV_DONTDUMP` (left out of core dumps). On drop the
//! bytes are zeroed before the pages are unlocked and freed.
//!
//! Locking is best effort: if the OS refuses (for example a low `RLIMIT_MEMLOCK` on Linux), the
//! value still lives in its own zeroed-on-drop allocation, just not locked. On non-Unix platforms
//! nothing is locked.

#![allow(unsafe_code)]

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::OnceLock;

use zeroize::Zeroize;

/// `N` secret bytes in their own locked page(s).
pub struct Locked<const N: usize> {
    ptr: NonNull<[u8; N]>,
    layout: Layout,
    locked: bool,
}

// SAFETY: `Locked` owns its allocation exclusively (like `Box<[u8; N]>`); the raw pointer is
// never shared, so moving it to or sharing `&Locked` with another thread is as safe as for a Box.
unsafe impl<const N: usize> Send for Locked<N> {}
unsafe impl<const N: usize> Sync for Locked<N> {}

fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        #[cfg(unix)]
        {
            // SAFETY: sysconf has no preconditions.
            let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if p > 0 {
                return p as usize;
            }
        }
        4096
    })
}

impl<const N: usize> Locked<N> {
    /// A zero-filled value. Fill it through `DerefMut`.
    pub fn zeroed() -> Self {
        let page = page_size();
        let size = N.max(1).div_ceil(page) * page;
        let layout = Layout::from_size_align(size, page).expect("page-sized layout");
        // SAFETY: `layout` has a non-zero size.
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(bytes) = NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout);
        };
        let locked = lock(bytes.as_ptr(), size);
        Locked {
            ptr: bytes.cast(),
            layout,
            locked,
        }
    }

    /// Copies `bytes` in and zeroes the source.
    pub fn take(bytes: &mut [u8; N]) -> Self {
        let mut l = Self::zeroed();
        l.copy_from_slice(bytes);
        bytes.zeroize();
        l
    }

    /// Whether the OS agreed to lock the pages into RAM.
    #[cfg(all(test, target_os = "macos"))]
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

#[cfg(unix)]
fn lock(ptr: *mut u8, size: usize) -> bool {
    // SAFETY: `ptr..ptr+size` is a live allocation we own, aligned to the page size.
    let ok = unsafe { libc::mlock(ptr.cast(), size) } == 0;
    #[cfg(target_os = "linux")]
    // SAFETY: as above; MADV_DONTDUMP only changes core-dump behaviour for these pages.
    unsafe {
        libc::madvise(ptr.cast(), size, libc::MADV_DONTDUMP);
    }
    ok
}

#[cfg(not(unix))]
fn lock(_ptr: *mut u8, _size: usize) -> bool {
    false
}

impl<const N: usize> Drop for Locked<N> {
    fn drop(&mut self) {
        // SAFETY: `ptr` is our live allocation of `layout.size()` bytes; we zero the whole
        // allocation (not just N bytes), unlock it if it was locked, then free it exactly once.
        unsafe {
            let base = self.ptr.as_ptr().cast::<u8>();
            std::slice::from_raw_parts_mut(base, self.layout.size()).zeroize();
            #[cfg(unix)]
            if self.locked {
                libc::munlock(base.cast(), self.layout.size());
            }
            dealloc(base, self.layout);
        }
    }
}

impl<const N: usize> Deref for Locked<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        // SAFETY: the allocation is at least N bytes, initialised (zeroed), and owned by self.
        unsafe { self.ptr.as_ref() }
    }
}

impl<const N: usize> DerefMut for Locked<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: as for `deref`, and `&mut self` guarantees exclusive access.
        unsafe { self.ptr.as_mut() }
    }
}

impl<const N: usize> Clone for Locked<N> {
    fn clone(&self) -> Self {
        let mut l = Self::zeroed();
        l.copy_from_slice(&**self);
        l
    }
}

impl<const N: usize> fmt::Debug for Locked<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Locked<{N}>(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_bytes_in_separate_locked_pages() {
        let mut src = [7u8; 32];
        let a = Locked::take(&mut src);
        assert_eq!(src, [0u8; 32], "source is zeroed");
        assert_eq!(*a, [7u8; 32]);
        let b = a.clone();
        assert_eq!(*b, *a);
        let (pa, pb) = (a.ptr.as_ptr() as usize, b.ptr.as_ptr() as usize);
        assert_eq!(pa % page_size(), 0, "page aligned");
        assert_ne!(pa / page_size(), pb / page_size(), "one page per secret");
        #[cfg(target_os = "macos")]
        assert!(a.is_locked(), "mlock works for small amounts on macOS");
        assert_eq!(format!("{a:?}"), "Locked<32>(<redacted>)");
    }
}
