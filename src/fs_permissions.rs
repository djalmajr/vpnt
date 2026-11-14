//! POSIX mode checks are performed by each caller. macOS extended ACL grants
//! can add rights independently of those bits, so inspect them as well.
use std::{fs::File, path::Path};

pub(crate) fn check_path(path: &Path, private: bool) -> Result<(), ()> {
    #[cfg(target_os = "macos")]
    {
        native::path(path, private)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, private);
        Ok(())
    }
}

pub(crate) fn check_file(file: &File, private: bool) -> Result<(), ()> {
    #[cfg(target_os = "macos")]
    {
        native::file(file, private)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (file, private);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod native {
    use std::{
        ffi::{CString, c_void},
        fs::File,
        io,
        os::{fd::AsRawFd, unix::ffi::OsStrExt},
        path::Path,
        ptr,
    };
    type Acl = *mut c_void;
    // Signatures and constants from the macOS SDK's sys/acl.h. libc does not
    // expose these Darwin-specific APIs. Returned ACLs are released with acl_free.
    unsafe extern "C" {
        fn acl_get_file(path: *const libc::c_char, kind: libc::c_int) -> Acl;
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> Acl;
        fn acl_get_entry(acl: Acl, index: libc::c_int, entry: *mut Acl) -> libc::c_int;
        fn acl_get_tag_type(entry: Acl, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_get_permset(entry: Acl, perms: *mut Acl) -> libc::c_int;
        fn acl_get_perm_np(perms: Acl, permission: libc::c_int) -> libc::c_int;
        fn acl_free(value: Acl) -> libc::c_int;
    }
    const EXTENDED: libc::c_int = 0x100;
    const ALLOW: libc::c_int = 1;
    const DENY: libc::c_int = 2;
    const MUTATING: [libc::c_int; 8] = [
        1 << 2,
        1 << 4,
        1 << 5,
        1 << 6,
        1 << 8,
        1 << 10,
        1 << 12,
        1 << 13,
    ];
    struct OwnedAcl(Acl);
    impl Drop for OwnedAcl {
        fn drop(&mut self) {
            // SAFETY: the owned non-null ACL came from acl_get_file/get_fd_np.
            unsafe {
                acl_free(self.0);
            }
        }
    }
    pub(super) fn path(path: &Path, private: bool) -> Result<(), ()> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| ())?;
        // SAFETY: CString is live and NUL-terminated; the API retains no pointer.
        inspect(unsafe { acl_get_file(path.as_ptr(), EXTENDED) }, private)
    }
    pub(super) fn file(file: &File, private: bool) -> Result<(), ()> {
        // SAFETY: the borrowed File keeps its descriptor live for this query.
        inspect(
            unsafe { acl_get_fd_np(file.as_raw_fd(), EXTENDED) },
            private,
        )
    }
    fn inspect(acl: Acl, private: bool) -> Result<(), ()> {
        if acl.is_null() {
            // Darwin reports ENOENT for an existing object with no extended ACL.
            // Callers have already checked existence/type/ownership (or hold FD).
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(())
            };
        }
        let acl = OwnedAcl(acl);
        let mut selector = 0; // ACL_FIRST_ENTRY; ACL_NEXT_ENTRY is -1 on Darwin.
        for _ in 0..=128 {
            let mut entry = ptr::null_mut();
            // SAFETY: ACL remains live, output points to a valid local pointer.
            let result = unsafe { acl_get_entry(acl.0, selector, &mut entry) };
            if result != 0 {
                return if result == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
                {
                    Ok(())
                } else {
                    Err(())
                };
            }
            selector = -1;
            let mut tag = 0;
            // SAFETY: entry belongs to the live ACL; tag is a valid output value.
            if entry.is_null() || unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
                return Err(());
            }
            if tag == DENY {
                continue;
            }
            if tag != ALLOW || private {
                return Err(());
            }
            let mut permissions = ptr::null_mut();
            // SAFETY: entry and its permission set remain valid with the ACL.
            if unsafe { acl_get_permset(entry, &mut permissions) } != 0 || permissions.is_null() {
                return Err(());
            }
            for permission in MUTATING {
                // SAFETY: the permission set is live and the constant is valid.
                if unsafe { acl_get_perm_np(permissions, permission) } != 0 {
                    return Err(());
                }
            }
        }
        Err(())
    }
}
