#![allow(unused_variables)]
use std::alloc::System;

#[global_allocator]
static A: System = System;
use libc::passwd;
use libc::{c_char, c_int, c_uchar, gid_t, group, size_t, uid_t};
use std::os::unix::fs::PermissionsExt;

use std::ffi::{CStr, CString};

use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Write;
use std::path::Path;
use std::process::Command;

extern crate ctor;
use ctor::*;

extern crate fern;
#[cfg(not(windows))]
extern crate syslog;
#[macro_use]
extern crate log;
extern crate bincode;
extern crate chrono;
extern crate pwhash;
extern crate rand;
extern crate rusoto_core;
#[macro_use]
extern crate lazy_static;

extern crate serde;
extern crate tokio_core;

mod aws;
mod logging;
mod utils;
use utils::*;
mod user_cache;
use aws::AWSUserCache;
use rusoto_core::Region;
use std::io::{Error, ErrorKind};
use user_cache::UserCache;

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
extern crate os_type;

mod mini_aws;

thread_local! {
    pub static DB_IDX: RefCell<u32> = RefCell::new(1);
}

const CACHE_FILE: &'static str = "/opt/nss-iam-user-cache.bin";
const REGION: Region = Region::UsEast1;

thread_local! {
    static CACHE: RefCell<AWSUserCache> =
    RefCell::new(AWSUserCache::with_loaded_entries(CACHE_FILE, REGION));
}

#[ctor]
/// This is an immutable static, evaluated at init time
static LOGGER: () = {
    let verbosity = if cfg!(debug_assertions) { 1 } else { 1 };
    let debug_log_name = "/opt/nss-iam-user.log";
    logging::setup_logging(verbosity, debug_log_name).unwrap_or(())
};

const SSHD_NAME: &'static str = "sshd";
lazy_static! {
    static ref SUDO_GROUP: &'static str = {
        match os_type::current_platform().os_type {
            os_type::OSType::CentOS | os_type::OSType::Redhat => "wheel",
            _ => "sudo",
        }
    };
}

const USER_SUDO_CMD: &'static str = "usermod -a -G";

fn add_user_to_sudo(username: &str, usergid: gid_t) -> bool {
    debug!(
        "groups of {} is {:?}",
        username,
        _get_group_list(username, usergid)
    );
    if _get_group_list(username, usergid).contains(&"sudo".to_owned()) {
        debug!("user '{}' already member of `sudo` group!", username);
        return true;
    }
    debug!(
        "In add_user_to_sudo, prog is: {}",
        _get_prog_name().unwrap_or("#cannot-get-name#".to_string())
    );

    let sudo_cmd = format!("{} {} {}", USER_SUDO_CMD, *SUDO_GROUP, username);
    debug!("sudo cmd is: {}", sudo_cmd);
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(sudo_cmd);
    match cmd.output() {
        Ok(result) => {
            dbg!(result);
            true
        }
        Err(e) => {
            warn!("Warning: cannot give sudo rights! Error: {}", e);
            false
        }
    }
}

fn file_contains_line(f: &fs::File, needle: &str) -> bool {
    let reader = std::io::BufReader::new(f);
    for line in reader.lines() {
        if let Ok(line) = line {
            if line.contains(needle) {
                return true;
            }
        }
    }
    false
}
/// key should contain ssh-rsa/dsa as well!!
fn add_ssh_key_to_user(username: &str, key: &str, duid: uid_t, dgid: gid_t) -> std::io::Result<()> {
    if !key.contains("ssh-") {
        error!("key should contain ssh-rsa/dsa prefix as well! Operation aborted");
        return Err(Error::new(
            ErrorKind::Other,
            "key should contain ssh-rsa/dsa prefix as well!",
        ));
    }

    let append_newline = !key.ends_with("\n");

    let ssh_home_path = "/home/".to_owned() + username + "/.ssh/";
    let authorized_keys_path = ssh_home_path.clone() + "authorized_keys";
    if !Path::new(&ssh_home_path).exists() {
        match fs::create_dir_all(&ssh_home_path) {
            Ok(_) => {
                info!("homedir for user '{}' was created successfully!", username);
            }
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Cannot create homedir {}!", &ssh_home_path),
                ))
            }
        }
    }

    let mut authorized_keys_file = OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open(&authorized_keys_path)?;
    let mut permissions = authorized_keys_file.metadata()?.permissions();
    permissions.set_mode(0o600);
    if !file_contains_line(&authorized_keys_file, key) {
        authorized_keys_file
            .write_all(key.as_bytes())
            .and_then(|_| {
                if append_newline {
                    authorized_keys_file
                        .write("\n".as_bytes())
                        .unwrap_or_else(|e| {
                            warn!("Wrote the key but cannot write a newline! Error is: {}", e);
                            //return 0, even without newline our key can be used
                            0
                        });
                }
                authorized_keys_file.sync_all()
            })?
    } else {
        debug!(
            "File {} already contains such key! nothing to do!",
            &authorized_keys_path
        );
    }

    if let Err(e) = chown(&authorized_keys_path, duid, dgid) {
        warn!(
            "Cannot call chown with file: '{}' for uid: '{}', gid: '{}'! Error: {}",
            &authorized_keys_path, duid, dgid, e
        );
    }

    Ok(())
}

#[derive(PartialEq)]
#[allow(dead_code)]
#[repr(C)]
pub enum NssStatus {
    TryAgain = -2,
    Unavailable,
    NotFound,
    Success,
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwent_r(
    passwd: *mut passwd,
    buffer: *mut char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    debug!("from _nss_iam_getpwent_r, passwd: {:?}", passwd);
    NssStatus::NotFound
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_setpwent(stayopen: c_int) -> NssStatus {
    debug!("from _nss_iam_setpwent, passwd: {:?}", stayopen);
    NssStatus::NotFound
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_endpwent() -> NssStatus {
    debug!("from _nss_iam_endpwent");
    NssStatus::NotFound
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getgrent_r(
    gbuf: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let idx = DB_IDX.with(|v| {
        *v.borrow_mut() += 1;
        v.borrow().clone()
    });
    // @TODO: wire actual AWS or dummy groups here
    if idx <= 1 {
        let mut g = Group::default();
        g.gr_gid = 27;
        g.gr_mem = vec!["testname".to_owned()];
        *gbuf = g.to_c(buf as *mut u8, buflen).expect("Cannot ");
        NssStatus::Success
    } else {
        NssStatus::NotFound
    }
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getgrnam_r(
    name: *const c_char,
    grp: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    debug!(
        "from _nss_iam_user_getgrnam_r; gid: {:?}",
        CStr::from_ptr(name)
    );
    NssStatus::NotFound
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getgrgid_r(
    gid: gid_t,
    grp: *mut group,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    debug!("from _nss_iam_user_getgrgid_r; gid: {}", gid);
    if !grp.is_null() {
        let g = Group::from(*grp);
        debug!("from _nss_iam_user_getgrgid_r; Group: {:?}", g);
        let mut g = Group::default();
        g.gr_gid = gid;
        g.gr_name = "testgroup".to_owned();
        g.gr_passwd = "x".to_owned();
        g.gr_mem = vec!["testname".to_owned()];

        match g.to_c(buf as *mut u8, buflen) {
            Ok(g) => {
                *grp = g;
            }
            Err(e) => {
                error!("Impossible!!! Cannot convert group. Error: {}", e);
                return NssStatus::NotFound;
            }
        };
    } else {
        debug!("from _nss_iam_user_getgrgid_r; Group: null");
        // should NotFound being returned here ???
    }
    NssStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwuid_r(
    uid: uid_t,
    passwd: *mut passwd,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    debug!("in getpwuid_r, uid: {:?}", uid);
    let mut result = NssStatus::NotFound;
    let mut cache = AWSUserCache::with_loaded_entries(CACHE_FILE, REGION);

    if let Some(ref user) = cache.get_by_uid(&uid) {
        *passwd = user
            .to_c_borrowed(buffer, buflen)
            .expect("Cannot convert to passwd!");
        result = NssStatus::Success;
    };
    cache.save().unwrap_or(());
    warn!("about to drop cache!");
    drop(cache);

    result
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwnam_r(
    name: *const c_char,
    passwd: *mut passwd,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    debug!("in getpwnam_r, name: {:?}", CStr::from_ptr(name),);

    let mut result = NssStatus::NotFound;
    let mut cache = AWSUserCache::with_loaded_entries(CACHE_FILE, REGION);

    let name = CStr::from_ptr(name).to_str().expect("String is invalid!");
    if let Some(ref user) = cache.get_by_name(name) {
        *passwd = user
            .to_c_borrowed(buffer, buflen)
            .expect("Cannot convert to passwd!");

        // add ssh key to user only if effective uid is 0 and caller was sshd
        if geteuid() == 0 {
            if let Some(progname) = _get_prog_name() {
                if progname.contains(SSHD_NAME) {
                    add_user_to_sudo(&name, user.pw_gid);
                }

                if let Some(ssh_keys) = &user.pw_ssh_key {
                    for key in ssh_keys.iter() {
                        match add_ssh_key_to_user(&name, key, user.pw_uid, user.pw_gid) {
                            Ok(_) => info!("SSH key was added!"),
                            Err(e) => error!("Cannot add SSH key! Error: {}", e),
                        }
                    }
                }
            }
        } else {
            debug!("Skipping adding a key, euid is: {}", geteuid());
        };
        result = NssStatus::Success;
    };
    cache.save().unwrap_or(());
    warn!("about to drop cache!");
    drop(cache);

    return result;
}
/*
gr_name: *mut c_char
gr_passwd: *mut c_char
gr_gid: gid_t
gr_mem: *mut *mut c_char
*/
#[derive(Debug, Clone, Default)]
struct Group {
    gr_name: String,
    gr_passwd: String,
    gr_gid: gid_t,
    gr_mem: Vec<String>,
}

impl From<group> for Group {
    fn from(group: group) -> Self {
        unsafe {
            // @TODO: copy instead of claiming ownership!

            let group_name = _get_new_cstring(group.gr_name)
                .into_string()
                .unwrap_or("noname".to_owned());
            // let mut group_members = vec![];
            //traverse **char (*mut *mut char)
            for i in 0.. {
                // get a pointer to *char
                let u = group.gr_mem.offset(i);
                if (*u).is_null() {
                    break;
                } else {
                    let member = CStr::from_ptr(*u)
                        .to_owned()
                        .into_string()
                        .expect("Cannot convert to rust-String!");

                    debug!("Group: {} has {}", group_name, member);
                    //group_members.push(member);
                }
            }

            Group::default()
        }
    }
}

impl Group {
    fn to_c(self, buffer: *mut c_uchar, buflen: size_t) -> Result<group, std::ffi::NulError> {
        unsafe {
            let mut g: group = std::mem::uninitialized();
            let buf = std::slice::from_raw_parts_mut(buffer, buflen);
            let mut offset = 0;

            let s = CString::new(self.gr_name)?;
            let s = s.to_bytes_with_nul();
            let remainder = &mut buf[offset..offset + s.len()];
            remainder.copy_from_slice(s);
            g.gr_name = buf.as_ptr().offset(offset as isize) as *mut i8;
            offset += s.len();

            let s = CString::new(self.gr_passwd)?;
            let s = s.to_bytes_with_nul();
            let remainder = &mut buf[offset..offset + s.len()];
            remainder.copy_from_slice(s);
            g.gr_passwd = buf.as_ptr().offset(offset as isize) as *mut i8;
            offset += s.len();

            g.gr_gid = self.gr_gid;

            let mut char_vec: Vec<*mut c_char> = Vec::new();
            // probably wrong

            for mem in self.gr_mem.into_iter() {
                let c_str = CString::new(mem)?;
                let cstr_len = c_str.to_bytes_with_nul().len();
                let dst = buf.as_mut_ptr().offset(offset as isize) as *mut i8;
                std::ptr::copy_nonoverlapping(c_str.as_ptr(), dst, cstr_len);
                char_vec.push(dst);
                offset += cstr_len;
            }
            char_vec.push(std::ptr::null_mut());
            let dst = buf.as_mut_ptr().offset(offset as isize) as *mut i8;
            std::ptr::copy(char_vec.as_ptr(), dst as *mut *mut i8, char_vec.len());
            //remainder.copy_from_slice(std::mem::transmute::<&[*mut i8], &[u8]>(char_vec.as_slice()));

            g.gr_mem = dst as *mut *mut i8;
            Ok(g)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passwd2 {
    pw_name: String,
    pw_passwd: String,
    pw_uid: uid_t,
    pw_gid: uid_t,
    pw_gecos: String,
    pw_dir: String,
    pw_shell: String,
    pw_ssh_key: Option<Vec<String>>,
}

impl Passwd2 {
    unsafe fn to_c_borrowed(&self, buffer: *mut c_char, buflen: size_t) -> Result<passwd, ()> {
        let mut pw: passwd;
        pw = std::mem::uninitialized();
        let buf = std::slice::from_raw_parts_mut(buffer, buflen);
        for i in 0..buflen {
            buf[i] = 0x00;
        }
        let mut offset = 0;

        let dst = buf.as_mut_ptr() as *mut u8;
        std::ptr::copy_nonoverlapping(
            self.pw_name.as_ptr(),
            dst.offset(offset as isize),
            self.pw_name.len(),
        );
        pw.pw_name = dst.offset(offset as isize) as *mut i8;
        offset += self.pw_name.len() + 1;

        std::ptr::copy_nonoverlapping(
            self.pw_passwd.as_ptr(),
            dst.offset(offset as isize),
            self.pw_passwd.len(),
        );
        pw.pw_passwd = dst.offset(offset as isize) as *mut i8;
        offset += self.pw_passwd.len() + 1;

        std::ptr::copy_nonoverlapping(
            self.pw_gecos.as_ptr(),
            dst.offset(offset as isize),
            self.pw_gecos.len(),
        );
        pw.pw_gecos = dst.offset(offset as isize) as *mut i8;
        offset += self.pw_gecos.len() + 1;

        std::ptr::copy_nonoverlapping(
            self.pw_dir.as_ptr(),
            dst.offset(offset as isize),
            self.pw_dir.len(),
        );
        pw.pw_dir = dst.offset(offset as isize) as *mut i8;
        offset += self.pw_dir.len() + 1;

        std::ptr::copy_nonoverlapping(
            self.pw_shell.as_ptr(),
            dst.offset(offset as isize),
            self.pw_shell.len(),
        );
        pw.pw_shell = dst.offset(offset as isize) as *mut i8;

        pw.pw_uid = self.pw_uid;
        pw.pw_gid = self.pw_gid;

        Ok(pw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_converter() {
        let _passwd = Passwd2 {
            pw_name: "test".to_owned(),
            pw_passwd: "x".to_owned(),
            pw_uid: 1000,
            pw_gid: 1000,
            pw_gecos: "test gecos".to_owned(),
            pw_dir: "/home/test".to_owned(),
            pw_shell: "/bin/bash".to_owned(),
            pw_ssh_key: None,
        };

        let mut v = Vec::with_capacity(1000);

        let buf_ptr: *mut i8 = v.as_mut_slice().as_mut_ptr();

        unsafe {
            let converted = _passwd.to_c_borrowed(buf_ptr, 1000).unwrap();
            assert_eq!(buf_ptr.offset(5), converted.pw_passwd);
            assert_eq!(CStr::from_ptr(buf_ptr.offset(5)).to_string_lossy(), "x");
            println!(
                "passwd pw_name: {:x?}, pw_passwd(should be +5): {:x?}, buf: {:x?}",
                converted.pw_name, converted.pw_passwd, buf_ptr
            );
            println!("hexdump: {:x?}", std::slice::from_raw_parts(buf_ptr, 100));
        }
    }

    #[test]
    fn test_passwd2() {
        let _passwd = Passwd2 {
            pw_name: "testname".to_owned(),
            pw_passwd: "testpasswd".to_owned(),
            pw_uid: 6000,
            pw_gid: 7000,
            pw_gecos: "test_gecos".to_owned(),
            pw_dir: "/home/testname".to_owned(),
            pw_shell: "/bin/bash".to_owned(),
            pw_ssh_key: None,
        };

        let mut v = Vec::with_capacity(1000);

        let buf_ptr: *mut i8 = v.as_mut_slice().as_mut_ptr();

        unsafe {
            let converted = _passwd.to_c_borrowed(buf_ptr, 1000).unwrap();
            let name_len = 9; // calc that actually: pw_name + 1
            assert_eq!(
                buf_ptr.offset(name_len as isize) as *mut i8,
                converted.pw_passwd
            );
            let actual_password =
                CStr::from_ptr(buf_ptr.offset(name_len as isize) as *mut i8).to_string_lossy();
            assert_eq!(actual_password, "testpasswd");
            println!(
                "passwd pw_name: {:x?}, pw_passwd(should be +5): {:x?}, buf: {:x?}",
                converted.pw_name, converted.pw_passwd, buf_ptr
            );
            println!("hexdump: {:x?}", std::slice::from_raw_parts(buf_ptr, 100));
        }
    }

    fn test_db_idx_call() -> NssStatus {
        let idx = DB_IDX.with(|v| {
            *v.borrow_mut() += 1;
            v.borrow().clone()
        });
        println!("DB_IDX: {}", idx);
        if idx <= 10 {
            NssStatus::Success
        } else {
            NssStatus::NotFound
        }
    }

    #[test]
    fn test_db_idx() {
        for _ in 0..9 {
            assert!(test_db_idx_call() == NssStatus::Success);
        }
        assert!(test_db_idx_call() == NssStatus::NotFound);
    }

    #[test]
    fn test_crypt_sha512() {
        // fixme: write an actual test
        println!("{}", _crypt("GenerateMe").unwrap());
    }

    #[test]
    fn test_my_groups() {
        // fixme: write an actual test
        println!("groups: {:?}", _get_group_list("l", 0))
    }
}
