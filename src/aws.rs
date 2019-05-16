use super::{utils::*, Group as NixGroup, Passwd2 as NixUser};
use crate::user_cache::StandardCache;
use crate::user_cache::UserCache;
use libc::uid_t;
use rusoto_core::Region;
use rusoto_iam::{
    GetSSHPublicKeyRequest, Group, Iam, IamClient, ListGroupsRequest, ListSSHPublicKeysRequest,
    ListUsersRequest, User, GetUserRequest
};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use chrono::prelude::*;

impl TryFrom<&User> for NixUser {
    type Error = Errors;

    fn try_from(user: &User) -> Result<Self, Self::Error> {
        let username = iam_username_to_nix(&user.user_name)?;
        let user_gid = iam_id_to_uid(&user.user_id);
        let user_dir = format!("/home/{}/", &username);
        let pw = Self {
            pw_name: username,
            pw_uid: user_gid,
            pw_dir: user_dir,
            pw_gecos: format!("AWS IAM user '{}'", user.user_id),
            pw_gid: user_gid,
            pw_shell: "/bin/bash".to_owned(),
            pw_passwd: _crypt(&get_alnum_string(24)).unwrap_or("x".to_owned()),
            pw_ssh_key: None,
        };

        Ok(pw)
    }
}

fn get_ssh_public_key(client: &IamClient, username: &str, key_id: &str) -> Option<String> {
    let request = GetSSHPublicKeyRequest {
        encoding: "SSH".to_owned(),
        ssh_public_key_id: key_id.to_owned(),
        user_name: username.to_owned(),
    };
    match client.get_ssh_public_key(request).sync() {
        Ok(output) => {
            debug!("output: {:?}", output);
            if let Some(pubkey) = output.ssh_public_key {
                Some(pubkey.ssh_public_key_body)
            } else {
                None
            }
        }
        Err(e) => {
            warn!("cannot get ssh public key details, error: {}", e);
            None
        }
    }
}

pub(crate) fn get_ssh_keys(client: &IamClient, username: String) -> Option<Vec<String>> {
    let request = ListSSHPublicKeysRequest {
        user_name: Some(username.clone()),
        ..Default::default()
    };

    let mut result: Vec<String> = Vec::new();

    match client.clone().list_ssh_public_keys(request).sync() {
        Ok(output) => {
            debug!("output: {:?}", output);
            if let Some(ssh_keys) = output.ssh_public_keys {
                ssh_keys
                    .iter()
                    .filter(|key| key.status == "Active")
                    .map(|key| {
                        let key_id = &key.ssh_public_key_id;
                        if let Some(key) = get_ssh_public_key(&client, &username, &key_id) {
                            result.push(key);
                        }
                    })
                    .for_each(drop);
            }
        }
        Err(e) => {
            warn!("Cannot list ssh_public keys, error: {}", e);
        }
    };
    Some(result)
}

pub(crate) fn get_users(region: Region) -> Option<Vec<User>> {
    let client = IamClient::new(region);
    let request = ListUsersRequest {
        ..Default::default()
    };

    match client.list_users(request).sync() {
        Ok(output) => Some(output.users),
        Err(e) => {
            println!("Cannot get userlist, error: {}", e);
            None
        }
    }
}

pub(crate) fn get_user(client: &IamClient, username: String) -> Option<User> {
    let request = GetUserRequest {
        user_name: Some(username)
    };

    match client.get_user(request).sync() {
        Ok(output) => Some(output.user),
        Err(e) => {
            println!("Cannot get user, error: {}", e);
            None
        }
    }
}

pub(crate) fn get_groups(region: Region) -> Option<Vec<Group>> {
    let client = IamClient::new(region);
    let request = ListGroupsRequest {
        ..Default::default()
    };

    match client.list_groups(request).sync() {
        Ok(output) => Some(output.groups),
        Err(e) => {
            println!("Cannot get grouplist, error: {}", e);
            None
        }
    }
}

pub struct AWSUserCache {
    inner: StandardCache<uid_t, NixUser>,
    client: IamClient,
}

impl AWSUserCache {
    pub fn new(filename: &str, region: Region) -> Self {
        Self {
            inner: StandardCache::new(filename),
            client: IamClient::new(region),
        }
    }

    fn refresh_cache(client: &IamClient, cache: &mut StandardCache<uid_t, NixUser>) {
        info!("timestamp: {}", cache.timestamp);
        if cache.timestamp + chrono::Duration::seconds(120) > Utc::now() {
            info!("No need to refresh cache yet");
            return 
        }
        let request = ListUsersRequest {
            ..Default::default()
        };

        match client.list_users(request).sync() {
            Ok(output) => {
                for user in output.users.iter() {
                    let user_ssh_keys = get_ssh_keys(client, user.user_name.clone());
                    if let Ok(mut pw_user) = NixUser::try_from(user) {
                        pw_user.pw_ssh_key = user_ssh_keys;
                        cache.set(pw_user.pw_uid, pw_user);
                    }
                }
            }
            Err(e) => {
                println!("Cannot get userlist, error: {}", e);
            }
        };
        cache.timestamp = Utc::now();
        cache.save().expect("Cannot save cache");
    }

    pub fn with_loaded_entries(filename: &str, region: Region) -> Self {
        let mut cache = Self::new(filename, region);
        AWSUserCache::refresh_cache(&cache.client, &mut cache.inner);

        cache
    }

    pub fn get_by_uid(&mut self, k: &uid_t) -> Option<&NixUser> {
        if self.inner.get(k).is_some() {
            return self.inner.get(k) 
        } else {
            // make an actual query
            // just refresh all entries in cache for now, figure it out later if that's the problem
            AWSUserCache::refresh_cache(&self.client, &mut self.inner);
            return self.inner.get(k)
        }
    }

    pub fn get_by_name(&mut self, name: &str) -> Option<&NixUser> {
        AWSUserCache::refresh_cache(&self.client, &mut self.inner);
        for (k,v) in self.inner.store.iter() {
            if v.pw_name.to_lowercase() == name.to_lowercase() {
                return Some(v)
            }
        }
        None
    }
}

impl Deref for AWSUserCache {
    type Target = StandardCache<uid_t, NixUser>;
    fn deref(&self) -> &StandardCache<uid_t, NixUser> {
        &self.inner
    }
}

impl DerefMut for AWSUserCache {
    fn deref_mut(&mut self) -> &mut StandardCache<uid_t, NixUser> {
        &mut self.inner
    }
}
