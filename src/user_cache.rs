use bincode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::hash::Hash;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::io::{Error, ErrorKind};
use std::os::unix::fs::OpenOptionsExt;

use libc::{mode_t, umask};

use chrono::prelude::*;
use std::str::FromStr;

/// UserCache Trait.
/// Used to implement caches for users. Currently isn't _that_ optimal, but for 10+ users it's good.
pub trait UserCache<K, V>
where
    K: Hash + Eq + Serialize,
    V: Serialize,
{
    /// get a value by a key
    fn get(&self, k: &K) -> Option<&V>;

    /// Insert a key, value pair
    fn set(&mut self, k: K, v: V);

    /// Remove a cached value
    fn remove(&mut self, k: &K) -> Option<V>;

    /// Remove all cached values
    fn clear(&mut self);

    /// save all cached entries somewhere
    fn save(&mut self) -> Result<(), std::io::Error>;
}

use std::path::{Path, PathBuf};

/// File-backed UserCache
#[derive(Serialize, Deserialize)]
pub struct StandardCache<K, V>
where
    K: Hash + Eq + Serialize,
{
    pub store: HashMap<K, V>,
    pub timestamp: DateTime<Utc>,
    #[serde(skip)]
    filename: String,
}

/// Reads content of `filename` to given `buffer`
fn read_to_buf(filename: &str, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
    let file = File::open(PathBuf::from_str(&filename).unwrap())?;
    let mut reader = BufReader::new(file);
    reader.read_to_end(buffer)
}

impl<K, V> StandardCache<K, V>
where
    K: Hash + Eq + Serialize + DeserializeOwned + std::fmt::Debug,
    V: Serialize + DeserializeOwned + std::fmt::Debug,
{
    pub fn new(filename: &str) -> Self {
        let mut store = HashMap::new();
        let mut timestamp = Utc::now();
        if Path::new(filename).exists() {
            // To avoid reallocations one can give vec a size hint
            // like vec.with_capacity(filesize);
            // but this isn't in hotpath
            let mut buffer = Vec::new();
            if read_to_buf(filename, &mut buffer).is_ok() {
                if let Ok(res) = bincode::deserialize::<StandardCache<K, V>>(&buffer) {
                    store = res.store;
                    timestamp = res.timestamp;
                    info!("Loaded cache from {}; Timestamp: {}", &filename, timestamp);
                } else {
                    warn!("Cannot read cache file, it's corrupted!");
                }
            }
        } else {
            info!("Cache file '{}' doesn't exist", filename);
            // we didn't find a cache file.
            // set timestamp back in time to force cache refresh
            timestamp = timestamp - chrono::Duration::seconds(6000);
        };

        Self {
            store: store,
            filename: filename.to_owned(),
            timestamp: timestamp,
        }
    }
}

/// Hashmap-backed storage, which got written to disk on each `save` call
/// Good for now, if that becomes a bottle-neck, one can batch writes
impl<'a, K, V> UserCache<K, V> for StandardCache<K, V>
where
    K: Hash + Eq + Serialize,
    V: Serialize + DeserializeOwned,
{
    fn get(&self, k: &K) -> Option<&V> {
        self.store.get(k)
    }

    fn set(&mut self, k: K, v: V) {
        self.store.insert(k, v);
    }

    fn remove(&mut self, k: &K) -> Option<V> {
        self.store.remove(k)
    }

    fn clear(&mut self) {
        self.store.clear();
    }

    fn save(&mut self) -> Result<(), std::io::Error> {
        // because it's a dylib that got injected into processes owned by different users we
        // should allow write to our cache file for everyone
        let old_umask: mode_t = unsafe { umask(0o011) };
        let mut file = OpenOptions::new();
        file.mode(0o666).create(true).write(true); // @FIXME: overwrite file on each save, could result in corruption if
                                                   // multiple programs with this library tried to save file simultaneously
                                                   // while we control the filename unwrap is safe
        let file = file.open(PathBuf::from_str(&self.filename).unwrap())?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Cannot serialize! Nested error: {}", e),
            )
        })?;
        unsafe {
            umask(old_umask); // restore original umask
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::rc::Rc;
    #[test]
    fn test_cache() {
        let mut filename = std::env::current_dir().unwrap();
        filename.push("test-cache.bin");
        let cache: Rc<RefCell<StandardCache<uid_t, Passwd2>>> =
            Rc::new(RefCell::new(StandardCache::new(filename.to_str().unwrap())));
        let uid = 777;

        let pw = Passwd2 {
            pw_name: "testname".to_owned(),
            pw_passwd: _crypt("test").unwrap_or("x".to_owned()),
            pw_uid: uid,
            pw_gid: 7000,
            pw_gecos: "test_gecos".to_owned(),
            pw_dir: "/home/testname".to_owned(),
            pw_shell: "/bin/bash".to_owned(),
            pw_ssh_key: None,
        };

        cache.borrow_mut().set(uid, pw);
        {
            let cache = cache.borrow_mut();
            let entry = cache.get(&uid).unwrap();
            assert_eq!(entry.pw_uid, uid);
            assert_eq!(entry.pw_name, "testname".to_owned());
        }

        cache.borrow_mut().save().unwrap();
    }

    #[test]
    fn test_cache_load() {
        let mut filename = std::env::current_dir().unwrap();
        filename.push("fixtures");
        filename.push("test-cache.bin");
        let cache: Rc<RefCell<StandardCache<uid_t, Passwd2>>> =
            Rc::new(RefCell::new(StandardCache::new(filename.to_str().unwrap())));

        let uid = 777;
        {
            let mut cache = cache.borrow_mut();
            let entry = cache
                .get(&uid)
                .expect("Cannot get entry from prebuilt fixtures cache!");
            assert_eq!(entry.pw_uid, uid);
            assert_eq!(entry.pw_name, "testname".to_owned());
        }
    }
}
