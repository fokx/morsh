//! Unix user lookup and session identity management.
//! Handles resolving user credentials, UID/GID, group lists, home directory,
//! and login shell from the system passwd/group databases.

#[cfg(unix)]
use std::ffi::{CStr, CString};
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use crate::error::{Result, TermError};

/// Resolved Unix user credentials and profile information.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Target Unix user ID.
    pub uid: libc::uid_t,
    /// Target primary group ID.
    pub gid: libc::gid_t,
    /// Absolute path to target user's home directory.
    pub dir: PathBuf,
    /// Path to user's preferred login shell executable.
    pub shell: String,
    /// Unix username.
    pub username: String,
    /// Supplementary group IDs associated with the user.
    pub groups: Vec<libc::gid_t>,
}

#[cfg(unix)]
impl UserInfo {
    /// Looks up user information by username in the system passwd database (thread-safe via getpwnam_r).
    pub fn lookup(username: &str) -> Result<Self> {
        let c_user = CString::new(username)
            .map_err(|e| TermError::Spawn(format!("Invalid username '{}': {}", username, e)))?;

        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buf_size: usize = 2048;
        let mut buf = vec![0 as libc::c_char; buf_size];

        loop {
            let rc = unsafe {
                libc::getpwnam_r(
                    c_user.as_ptr(),
                    pwd.as_mut_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut result,
                )
            };

            if rc == libc::ERANGE {
                buf_size *= 2;
                buf.resize(buf_size, 0);
                continue;
            }

            if rc != 0 || result.is_null() {
                return Err(TermError::Spawn(format!(
                    "User '{}' not found in system passwd database",
                    username
                )));
            }

            break;
        }

        let pwd_ref = unsafe { pwd.assume_init() };
        let uid = pwd_ref.pw_uid;
        let gid = pwd_ref.pw_gid;

        let dir = unsafe {
            if !pwd_ref.pw_dir.is_null() {
                let s = CStr::from_ptr(pwd_ref.pw_dir);
                PathBuf::from(s.to_str().unwrap_or("/"))
            } else {
                PathBuf::from("/")
            }
        };

        let shell = unsafe {
            if !pwd_ref.pw_shell.is_null() {
                let s = CStr::from_ptr(pwd_ref.pw_shell);
                s.to_str().unwrap_or("/bin/sh").to_string()
            } else {
                "/bin/sh".to_string()
            }
        };

        let mut ngroups: libc::c_int = 64;
        let mut groups = vec![0 as libc::gid_t; 64];
        let res = unsafe {
            libc::getgrouplist(c_user.as_ptr(), gid, groups.as_mut_ptr(), &mut ngroups)
        };
        if res == -1 && ngroups > 64 {
            groups.resize(ngroups as usize, 0);
            unsafe {
                libc::getgrouplist(c_user.as_ptr(), gid, groups.as_mut_ptr(), &mut ngroups);
            }
        }
        if ngroups > 0 {
            groups.truncate(ngroups as usize);
        } else {
            groups.clear();
        }

        Ok(Self {
            uid,
            gid,
            dir,
            shell,
            username: username.to_string(),
            groups,
        })
    }
}
