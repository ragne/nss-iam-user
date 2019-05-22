use libc::{c_char, c_int, gid_t, uid_t};
use pwhash::unix::crypt;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::ffi::{CStr, CString};
use std::hash::{Hash, Hasher};
use std::iter;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const UID_MIN: u64 = 2000;
const UID_MAX: u64 = 5000;
const USER_NAME_MAX_LENGTH: usize = 32;

fn utf8_truncate(input: &mut String, maxsize: usize) {
    let mut utf8_maxsize = input.len();
    if utf8_maxsize >= maxsize {
        {
            let mut char_iter = input.char_indices();
            while utf8_maxsize >= maxsize {
                utf8_maxsize = match char_iter.next_back() {
                    Some((index, _)) => index,
                    _ => 0,
                };
            }
        }
        input.truncate(utf8_maxsize);
    }
}

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

#[allow(unused)]
pub(crate) fn get_alnum_string(size: usize) -> String {
    let mut rng = rand::thread_rng();
    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(size)
        .collect()
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

    if result == -1 {
        Vec::new()
    } else {
        for gid in groups.iter().take(result as usize) {
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

#[derive(Debug)]
pub enum Errors {
    InvalidChar(String),
}

/// Tries to convert IAM username to *nux username
/// The rules for *nix usernames:
///  - No more that `USER_NAME_MAX_LENGTH` length
///  - Should consists only of alphanumeric chars
///  - All chars that allowed in IAM user names are replaced with `_` underscore
pub(crate) fn iam_username_to_nix(name: &str) -> Result<String, Errors> {
    #[inline]
    fn is_valid(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_' || c == '-'
    }

    if name.len() < USER_NAME_MAX_LENGTH && name.chars().all(is_valid) {
        Ok(name.to_ascii_lowercase())
    } else {
        let result: Result<String, Errors> = name
            .chars()
            .map(|x| {
                if x == '@' || x == ':' || x == '/' || x == ',' || x == '.' || x == '=' || x == '+'
                {
                    Ok('_')
                } else if is_valid(x) {
                    Ok(x.to_ascii_lowercase())
                } else {
                    Err(Errors::InvalidChar(format!(
                        "Name contains invalid char: '{}'",
                        x
                    )))
                }
            })
            .collect();
        result.map(|mut r| {
            utf8_truncate(&mut r, USER_NAME_MAX_LENGTH);
            Ok(r)
        })?
    }
}

pub(crate) fn iam_id_to_uid(id: &str) -> uid_t {
    let mut s = DefaultHasher::new();
    id.hash(&mut s);
    let mut rem = s.finish() % UID_MAX;
    if rem < UID_MIN {
        rem += UID_MIN;
    }

    assert!(
        rem < UID_MAX,
        format!("Shouldn't be possible, rem: {}", rem)
    );

    rem as uid_t
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iam_username_to_nix() {
        let long_username = get_alnum_string(USER_NAME_MAX_LENGTH + 2);
        let names = vec!["user.1", "HelloUser", "In𝓥alid", &long_username];
        assert_eq!(iam_username_to_nix(names[0]).unwrap(), "user_1");
        assert_eq!(iam_username_to_nix(names[1]).unwrap(), "hellouser");
        assert!(iam_username_to_nix(names[2]).is_err());
        assert!(iam_username_to_nix(names[3]).unwrap().len() <= USER_NAME_MAX_LENGTH);
    }

    #[test]
    fn test_iam_id_to_uid() {
        let ids: Vec<String> = (0..10).map(|_| get_alnum_string(21)).collect();
        let uids: Vec<uid_t> = ids.iter().map(|id| iam_id_to_uid(&id)).collect();

        for uid in uids.iter() {
            assert!(
                (*uid as u64) < UID_MAX && (*uid as u64) > UID_MIN,
                format!("uid is: {}", uid)
            );
        }
    }
}
