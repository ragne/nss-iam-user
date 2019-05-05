use libc::{c_char, c_int, gid_t, uid_t};
use pwhash::unix::crypt;
use rand::Rng;
use std::env;
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(crate) fn _crypt(pass: &str) -> Result<String, pwhash::error::Error> {
    let salt: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .collect();
    Ok(crypt(pass, &format!("$6${}$", salt))?)
}

pub(crate) fn _get_prog_name() -> Option<String> {
    match env::current_exe() {
        Ok(exe_path) => Some(exe_path.display().to_string()),
        Err(e) => {
            println!("failed to get current exe path: {}", e);
            None
        }
    }
}

pub(crate) fn chown<P: AsRef<Path>>(path: P, duid: uid_t, dgid: gid_t) -> std::io::Result<()> {
    let path = path.as_ref();
    let s = CString::new(path.as_os_str().as_bytes()).unwrap();
    let ret = unsafe { libc::chown(s.as_ptr(), duid, dgid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[inline]
pub fn geteuid() -> uid_t {
    unsafe { libc::geteuid() }
}

pub(crate) unsafe fn _get_new_cstring(ptr: *const c_char) -> CString {
    let blank = CString::new("").unwrap();
    if ptr.is_null() {
        blank
    } else {
        CString::new(CStr::from_ptr(ptr).to_bytes()).unwrap_or(blank)
    }
}

pub(crate) fn _get_group_list(user: &str, group: gid_t) -> Vec<String> {
    let ngroups = 32;
    let mut groups: Vec<gid_t> = vec![0; ngroups];
    let mut actual_groups = Vec::new();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = unsafe {
        let user = CString::new(user).unwrap();
        libc::getgrouplist(
            user.as_ptr(),
            group,
            groups.as_mut_ptr(),
            &mut (ngroups as c_int) as *mut c_int,
        )
    };

    #[cfg(all(unix, target_os = "macos"))]
    let result = unsafe {
        let user = CString::new(user).unwrap();
        libc::getgrouplist(
            user.as_ptr(),
            group as i32,
            groups.as_mut_ptr() as *mut i32,
            &mut (ngroups as c_int) as *mut c_int,
        )
    };

    println!("result: {}/{:?}", result, groups);
    if result == -1 {
        Vec::new()
    } else {
        for gid in groups.iter().take(result as usize) {
            println!("gid is {}", *gid);
            unsafe {
                let gr = libc::getgrgid(*gid);
                if !gr.is_null() {
                    if let Ok(grp) = _get_new_cstring((*gr).gr_name).into_string() {
                        actual_groups.push(grp)
                    }
                }
            }
        }
        actual_groups
    }
}
