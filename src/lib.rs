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
extern crate rusoto_iam;
extern crate serde;

mod aws;
mod logging;
mod utils;
use utils::*;
mod user_cache;
use aws::AWSUserCache;
use rusoto_core::Region;
use user_cache::UserCache;

use serde::{Deserialize, Serialize};
use std::cell::RefCell;

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
    let verbosity = if cfg!(debug_assertions) { 1 } else { 0 };
    let debug_log_name = "/opt/nss-iam-user.log";
    logging::setup_logging(verbosity, debug_log_name).unwrap();
};

const SSHD_NAME: &'static str = "sshd";
const USER_SUDO_CMD: &'static str = "usermod -a -G sudo";
const TEST_SSH_KEY: &'static str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC27BaaJmBW6BD+KxaVXjgGUj9gmRUDG4EXpr7diBbu6mXQYbRgUa6vbTfe4wNYyfu9H0GPD+OzYPHZoT4pNU0vfzeNmSIOdMHn89kM64+ytiHyWaMt9eqD1nR+iPqHgn4JmZ+G9u6kMctocXbuuQsr1uAtz06H5mIxgscY7TF++l/Udiq8koLQm86JkCYTDqyYMwiJjFjU6ufgxG+Pd6byolKdUXIxXXTkAJpmLsRaWRpwr0RH0Nzla276oQc0+cIsa+z/Tr4+EbzVcg8ifO1F5zCGcr/BYtde5+VaomBpPLLlLqNOr6QE/VJFiQAi5YGYwpKj8GmYM6x1Nb1rG27P l@testkey";

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
        _get_prog_name().unwrap()
    );

    let sudo_cmd = USER_SUDO_CMD.to_owned() + " " + username;
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
fn add_ssh_key_to_user(username: &str, key: &str, duid: uid_t, dgid: gid_t) -> bool {
    if !key.contains("ssh-") {
        error!("key should contain ssh-rsa/dsa prefix as well! Operation aborted");
        return false;
    }

    let append_newline = !key.ends_with("\n");

    let ssh_home_path = "/home/".to_owned() + username + "/.ssh/";
    let authorized_keys_path = ssh_home_path.clone() + "authorized_keys";
    if !Path::new(&ssh_home_path).exists() {
        match fs::create_dir_all(ssh_home_path) {
            Ok(_) => {
                info!("homedir for user '{}' was created successfully!", username);
            }
            Err(_) => return false,
        }
    }

    let mut authorized_keys_file = OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open(&authorized_keys_path)
        .unwrap();
    let mut permissions = authorized_keys_file.metadata().unwrap().permissions();
    permissions.set_mode(0o600);
    if !file_contains_line(&authorized_keys_file, key) {
        match authorized_keys_file.write_all(key.as_bytes()) {
            Ok(_) => {
                if append_newline {
                    authorized_keys_file
                        .write("\n".as_bytes())
                        .unwrap_or_else(|e| {
                            warn!("Wrote the key but cannot write a newline! Error is: {}", e);
                            //return 0, even without newline our key can be used
                            0
                        });
                }
                authorized_keys_file.sync_all().unwrap()
            }
            Err(e) => {
                error!(
                    "Cannot write file {}! Underlying error: {}",
                    &authorized_keys_path, e
                );
                return false;
            }
        }
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

    true
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

// fn log(msg: String) {
//     match env::current_exe() {
//     Ok(exe_path) => println!("Path of this executable is: {}",
//                              exe_path.display()),
//     Err(e) => println!("failed to get current exe path: {}", e),
//     };
//     let mut file = OpenOptions::new().create(true).append(true).open("/opt/bar.txt").unwrap();
//     let mut permissions = file.metadata().unwrap().permissions();
//     permissions.set_mode(0o666);
//     file.write_all(msg.as_bytes()).unwrap();
//     file.write("\n".as_bytes()).unwrap();
//     file.sync_all().unwrap();
// }

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

// Not sure that nss even implements that bridge
// #[no_mangle]
// pub unsafe extern "C" fn _nss_iam_user_getgrouplist(user: *const c_char, group: gid_t, groups: *mut gid_t, ngroups: *mut c_int, errnop: *mut c_int) -> NssStatus {
//     debug!("from _nss_iam_user_getgrouplist; user: {:?}, group: {:?}", CStr::from_ptr(user), *groups);
//     NssStatus::NotFound
// }

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
    CACHE.with(|ref v| {
            let cache = (*v).borrow();
            if let Some(ref user) = cache.get(&uid) {
                println!("got user {:?} from cache", user);
                *passwd = user.to_c_borrowed(buffer, buflen).expect("Cannot convert to passwd!");
            };
        });
    

    if !passwd.is_null() && !(*passwd).pw_name.is_null() {
        debug!("Got passwd: {:?}", Passwd::from(*passwd));
        if uid == 777 {
            debug!("Got magic uid 777! Constructing pw_entry for that...");
            let pw = Passwd2 {
                pw_name: "testname".to_owned(),
                pw_passwd: _crypt("test").unwrap_or("x".to_owned()),
                pw_uid: 777,
                pw_gid: 7000,
                pw_gecos: "test_gecos".to_owned(),
                pw_dir: "/home/testname".to_owned(),
                pw_shell: "/bin/bash".to_owned(),
                pw_ssh_key: None,
            };

            *passwd = pw.to_c(buffer as *mut u8, buflen).expect("Cannot convert to passwd!");
            return NssStatus::Success;
        };

        if !errnop.is_null() {
            warn!("Errnop isn't null: {:x?}", *errnop);
        }
        return NssStatus::NotFound;
    }
    debug!("from _nss_iam_user_getpwuid_r; uid: {:?}, bailed out!", uid);
    //*errnop = ENOENT as *mut i32;
    return NssStatus::NotFound;
}

#[no_mangle]
pub unsafe extern "C" fn _nss_iam_user_getpwnam_r(
    name: *const c_char,
    passwd: *mut passwd,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus {
    debug!(
        "in getpwnam_r, name: {:?}, passwd: {:?}",
        CStr::from_ptr(name),
        Passwd::from(*passwd)
    );
    let rng = rand::thread_rng();
    let _name = CStr::from_ptr(name).to_string_lossy();
    if _name.contains("test") {
        debug!("name contains test");
        let test_gid = 777;
        let _passwd = Passwd {
            pw_name: CStr::from_ptr(_name.as_ptr() as *mut i8),
            pw_passwd: &CString::new(_crypt("test").unwrap_or("x".to_owned()))
                .expect("CString::new failed!"),
            pw_uid: 777,
            pw_gid: test_gid,
            pw_gecos: &CString::new("").expect("CString::new failed!"),
            pw_dir: &CString::new("/home/".to_owned() + &_name).expect("CString::new failed!"),
            pw_shell: &CString::new("/bin/bash").expect("CString::new failed!"),
        };
        //let pass = &mut *(passwd);
        //let rusty_passwd: Passwd = (*passwd).into();
        let c_passwd: passwd = _passwd.to_c(buffer, buflen).unwrap();

        // add ssh key to user only if effective uid is 0 and caller was sshd
        if geteuid() == 0 {
            if let Some(progname) = _get_prog_name() {
                if progname.contains(SSHD_NAME) {
                    add_user_to_sudo(&_name, test_gid);
                }

                if add_ssh_key_to_user(&_name, TEST_SSH_KEY, c_passwd.pw_uid, c_passwd.pw_gid) {
                    info!("SSH key was added!");
                } else {
                    error!("Cannot add SSH key!");
                }
            }
        } else {
            debug!("Skipping adding a key, euid is: {}", geteuid());
        }
        *passwd = c_passwd;
    } else {
        debug!(
            "name doesn't contain test, name: {:?}. Not for us, returning NotFound",
            _name
        );
        return NssStatus::NotFound;
    }
    debug!(
        "from _nss_iam_user_getpwnam_r; name: {:?}, passwd: {:?}",
        CStr::from_ptr(name),
        Passwd::from(*passwd)
    );
    NssStatus::Success
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

            // let mut buf: Vec<c_char> = Vec::with_capacity(CStr::from_ptr(group.gr_passwd).to_bytes_with_nul().len());
            // std::ptr::copy(group.gr_passwd, buf.as_mut_ptr(), buf.capacity());
            // let group_password = CString::from_raw(buf.as_mut_ptr())
            //     .into_string().unwrap_or("nopasswd".to_owned());
            // let group_gid = group.gr_gid;
            // Group {
            //     gr_name: group_name,
            //     gr_passwd: group_password,
            //     gr_gid: group_gid,
            //     gr_mem: group_members
            // }
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
        let mut offset = 0;

        let dst = buf.as_mut_ptr() as *mut u8;
        std::ptr::copy_nonoverlapping(self.pw_name.as_ptr(), dst.offset(offset as isize), self.pw_name.len()+1);
        pw.pw_name = dst.offset(offset as isize) as *mut i8;
        offset += self.pw_name.len()+1;
        

        std::ptr::copy_nonoverlapping(self.pw_passwd.as_ptr(), dst.offset(offset as isize), self.pw_passwd.len()+1);
        pw.pw_passwd = dst.offset(offset as isize) as *mut i8;
        offset += self.pw_passwd.len()+1;

        std::ptr::copy_nonoverlapping(self.pw_gecos.as_ptr(), dst.offset(offset as isize), self.pw_gecos.len()+1);
        pw.pw_gecos = dst.offset(offset as isize) as *mut i8;
        offset += self.pw_gecos.len()+1;

        std::ptr::copy_nonoverlapping(self.pw_dir.as_ptr(), dst.offset(offset as isize), self.pw_dir.len()+1);
        pw.pw_dir = dst.offset(offset as isize) as *mut i8;
        offset += self.pw_dir.len()+1;

        std::ptr::copy_nonoverlapping(self.pw_shell.as_ptr(), dst.offset(offset as isize), self.pw_shell.len()+1);
        pw.pw_shell = dst.offset(offset as isize) as *mut i8;

        pw.pw_uid = self.pw_uid;
        pw.pw_gid = self.pw_gid;

        Ok(pw)
    }

    unsafe fn to_c(self, buffer: *mut c_uchar, buflen: size_t) -> Result<passwd, ()> {
        let mut pw: passwd;
        pw = std::mem::uninitialized();
        let buf = std::slice::from_raw_parts_mut(buffer, buflen);
        let mut offset = 0;
        let s = CString::new(self.pw_name).expect("Cannot create CString");
        let s = s.to_bytes_with_nul();
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_name = buf.as_ptr().offset(offset as isize) as *mut i8;
        offset += s.len();

        let s = CString::new(self.pw_passwd).expect("Cannot create CString");
        let s = s.to_bytes_with_nul();
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_passwd = buf.as_ptr().offset(offset as isize) as *mut i8;
        offset += s.len();

        let s = CString::new(self.pw_gecos).expect("Cannot create CString");
        let s = s.to_bytes_with_nul();
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_gecos = buf.as_ptr().offset(offset as isize) as *mut i8;
        offset += s.len();

        let s = CString::new(self.pw_dir).expect("Cannot create CString");
        let s = s.to_bytes_with_nul();
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_dir = buf.as_ptr().offset(offset as isize) as *mut i8;
        offset += s.len();

        let s = CString::new(self.pw_shell).expect("Cannot create CString");
        let s = s.to_bytes_with_nul();
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_shell = buf.as_ptr().offset(offset as isize) as *mut i8;

        pw.pw_uid = self.pw_uid;
        pw.pw_gid = self.pw_gid;

        Ok(pw)
    }
}

#[derive(Debug, Clone)]
struct Passwd<'a> {
    pw_name: &'a CStr,
    pw_passwd: &'a CStr,
    pw_uid: uid_t,
    pw_gid: uid_t,
    pw_gecos: &'a CStr,
    pw_dir: &'a CStr,
    pw_shell: &'a CStr,
}

impl<'a> Passwd<'a> {
    unsafe fn to_c(self, buffer: *mut c_char, buflen: size_t) -> Result<passwd, ()> {
        let mut pw: passwd = self.clone().into();
        let buf = std::slice::from_raw_parts_mut(buffer, buflen);
        let mut offset = 0;
        let s = &*(self.pw_name.to_bytes_with_nul() as *const _ as *const [i8]);
        trace!(
            "offset: {}, s: {:x?}, len: {}, str: {}",
            offset,
            s,
            s.len(),
            self.pw_name.to_str().unwrap()
        );
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_name = buf.as_ptr().offset(offset as isize) as *mut i8;
        offset += s.len();

        trace!("offset: {}", offset);
        let s = &*(self.pw_passwd.to_bytes_with_nul() as *const _ as *const [i8]);
        trace!(
            "offset: {}, s: {:x?}, len: {}, str: {}",
            offset,
            s,
            s.len(),
            self.pw_passwd.to_str().unwrap()
        );
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_passwd = buf.as_ptr().offset(offset as isize) as *mut i8;
        offset += s.len();

        trace!("offset: {}", offset);
        let s = &*(self.pw_gecos.to_bytes_with_nul() as *const _ as *const [i8]);
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_gecos = buf.as_ptr().offset(offset as isize) as *mut i8;
        offset += s.len();

        trace!("offset: {}", offset);
        let s = &*(self.pw_dir.to_bytes_with_nul() as *const _ as *const [i8]);
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_dir = buf.as_ptr().offset(offset as isize) as *mut i8;
        offset += s.len();

        trace!("offset: {}", offset);
        let s = &*(self.pw_shell.to_bytes_with_nul() as *const _ as *const [i8]);
        let remainder = &mut buf[offset..offset + s.len()];
        remainder.copy_from_slice(s);
        pw.pw_shell = buf.as_ptr().offset(offset as isize) as *mut i8;

        // log(format!("Last offset: {}", offset));

        Ok(pw)
    }
}

impl<'a> From<passwd> for Passwd<'a> {
    fn from(passwd: passwd) -> Self {
        unsafe {
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
}
#[cfg(target_os = "linux")]
impl<'a> Into<passwd> for Passwd<'a> {
    fn into(self) -> passwd {
        passwd {
            pw_name: self.pw_name.as_ptr() as *mut i8,
            pw_passwd: self.pw_passwd.as_ptr() as *mut i8,
            pw_uid: self.pw_uid,
            pw_gid: self.pw_gid,
            pw_gecos: self.pw_gecos.as_ptr() as *mut i8,
            pw_dir: self.pw_dir.as_ptr() as *mut i8,
            pw_shell: self.pw_shell.as_ptr() as *mut i8,
        }
    }
}

#[cfg(target_os = "macos")]
impl<'a> Into<passwd> for Passwd<'a> {
    fn into(self) -> passwd {
        passwd {
            pw_name: self.pw_name.as_ptr() as *mut i8,
            pw_passwd: self.pw_passwd.as_ptr() as *mut i8,
            pw_uid: self.pw_uid,
            pw_gid: self.pw_gid,
            pw_gecos: self.pw_gecos.as_ptr() as *mut i8,
            pw_dir: self.pw_dir.as_ptr() as *mut i8,
            pw_shell: self.pw_shell.as_ptr() as *mut i8,
            pw_change: 0,
            pw_class: self.pw_shell.as_ptr() as *mut i8,
            pw_expire: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_converter() {
        let _passwd = Passwd {
            pw_name: &CString::new("test").expect("Cannot create name"),
            pw_passwd: &CString::new("nopasswd").expect("CString::new failed!"),
            pw_uid: 1000,
            pw_gid: 1000,
            pw_gecos: &CString::new("").expect("CString::new failed!"),
            pw_dir: &CString::new("/home/test").expect("CString::new failed!"),
            pw_shell: &CString::new("/bin/bash").expect("CString::new failed!"),
        };

        let mut v = Vec::with_capacity(1000);

        let buf_ptr: *mut i8 = v.as_mut_slice().as_mut_ptr();

        unsafe {
            let converted = _passwd.to_c(buf_ptr, 1000).unwrap();
            assert_eq!(buf_ptr.offset(5), converted.pw_passwd);
            assert_eq!(
                CStr::from_ptr(buf_ptr.offset(5)).to_string_lossy(),
                "nopasswd"
            );
            println!(
                "passwd pw_name: {:x?}, pw_passwd(should be +5): {:x?}, buf: {:x?}",
                converted.pw_name, converted.pw_passwd, buf_ptr
            );
            println!("hexdump: {:x?}", std::slice::from_raw_parts(buf_ptr, 100));
            println!("{:?}", Passwd::from(converted));
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

        let buf_ptr: *mut u8 = v.as_mut_slice().as_mut_ptr();

        unsafe {
            let converted = _passwd.to_c(buf_ptr, 1000).unwrap();
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
