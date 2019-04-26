use libc::passwd;
use libc::{c_char, size_t, hostent, AF_INET, c_int, uid_t};
use libc::{ENOENT, ERANGE};

use std::str::FromStr;
use std::ffi::CStr;
use std::fs::File;
use std::io::prelude::*;
use std::fs::OpenOptions;

#[allow(dead_code)]
#[repr(C)]
pub enum NssStatus {
    TryAgain = -2,
    Unavailable,
    NotFound,
    Success,
}

// #[no_mangle]
// pub unsafe extern "C" fn _nss_openvpn_gethostbyname2_r(
//     name: *const c_char,
//     af: i32,
//     result: *mut hostent,
//     buffer: *mut c_char,
//     buflen: size_t,
//     errnop: *mut i32,
//     h_errnop: *mut i32,
// ) -> NssStatus {
//     if af != AF_INET {
//         *errnop = ENOENT;
//         return NssStatus::NotFound;
//     }

//     _nss_iam_gethostbyname_r(name, result, buffer, buflen, errnop, h_errnop)
// }



fn log(msg: String) {
    let mut file = OpenOptions::new().create(true).append(true).open("/tmp/bar.txt").unwrap();
    file.write_all(msg.as_bytes()).unwrap();
    file.write("\n".as_bytes()).unwrap();
    file.sync_all().unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_setpwent_locked(stayopen: c_int) -> NssStatus {
    log(format!("from _nss_iam_user_setpwent, stayopen: {}", stayopen));
    NssStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwbynam_r(name: *const c_char, passwd: *mut passwd, buffer: *mut c_char, buflen: size_t, errnop: *mut c_int) -> NssStatus {
    log(format!("from _nss_iam_getpwbynam_r, name: {:?}, passwd: {:?}", name, passwd));
    NssStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwbyuid_r(uid: uid_t, passwd: *mut passwd, buffer: *mut char, buflen: size_t, errnop: *mut c_int) -> NssStatus {
    log(format!("from _nss_iam_getpwbyuid_r, uid: {:?}, passwd: {:?}", uid, passwd));
    NssStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwent_r(passwd: *mut passwd, buffer: *mut char, buflen: size_t, errnop: *mut c_int) -> NssStatus {
    log(format!("from _nss_iam_getpwent_r, passwd: {:?}", passwd));
    NssStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_setpwent(stayopen: c_int) -> NssStatus{ //passwd: *mut passwd, buffer: *mut char, buflen: size_t, errnop: *mut c_int) -> NssStatus {
    log(format!("from _nss_iam_setpwent, passwd: {:?}", stayopen));
    NssStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_endpwent() -> NssStatus {
    log(format!("from _nss_iam_endpwent"));
    NssStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwuid_r(uid: uid_t, passwd: *mut passwd, buffer: *mut char, buflen: size_t, errnop: *mut c_int) -> NssStatus {
    log(format!("from _nss_iam_user_getpwuid_r; uid: {:?}, passwd: {:?}", uid, passwd));
    NssStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwnam_r(name: *const c_char, passwd: *mut passwd, buffer: *mut c_char, buflen: size_t, errnop: *mut c_int) -> NssStatus {
    let pass = &mut *(passwd);
    let rusty_passwd = Passwd::from_passwd(*passwd);
    log(format!("from _nss_iam_user_getpwnam_r; name: {:?}, passwd: {:?}", CStr::from_ptr(name), rusty_passwd));
    NssStatus::Success
}

#[derive(Debug)]
struct Passwd<'a> {
    pw_name: &'a CStr,
    pw_passwd: &'a CStr,
    pw_uid: uid_t,
    pw_gid: uid_t,
    pw_gecos:  &'a CStr,
    pw_dir:  &'a CStr,
    pw_shell:  &'a CStr,
}

impl<'a> Passwd<'a> {
    unsafe fn from_passwd(passwd: passwd) -> Self {
        Self {
            pw_name: CStr::from_ptr(passwd.pw_name),
            pw_passwd: CStr::from_ptr(passwd.pw_passwd),
            pw_uid: passwd.pw_uid,
            pw_gid: passwd.pw_gid,
            pw_gecos: CStr::from_ptr(passwd.pw_gecos),
            pw_dir: CStr::from_ptr(passwd.pw_dir),
            pw_shell: CStr::from_ptr(passwd.pw_shell),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
