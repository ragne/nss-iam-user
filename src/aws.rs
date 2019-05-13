use super::{utils::*, Group as NixGroup, Passwd2 as NixUser};
use crate::user_cache::StandardCache;
use crate::user_cache::UserCache;
use libc::uid_t;
use rusoto_core::Region;
use rusoto_iam::{
    GetSSHPublicKeyRequest, Group, Iam, IamClient, ListGroupsRequest, ListSSHPublicKeysRequest,
    ListUsersRequest, User,
};
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};

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

    pub fn with_loaded_entries(filename: &str, region: Region) -> Self {
        let mut cache = Self::new(filename, region);
        let request = ListUsersRequest {
            ..Default::default()
        };

        match cache.client.list_users(request).sync() {
            Ok(output) => {
                for user in output.users.iter() {
                    let user_ssh_keys = get_ssh_keys(&cache.client, user.user_name.clone());
                    if let Ok(mut pw_user) = NixUser::try_from(user) {
                        pw_user.pw_ssh_key = user_ssh_keys;
                        cache.inner.set(pw_user.pw_uid, pw_user);
                    }
                }
            }
            Err(e) => {
                println!("Cannot get userlist, error: {}", e);
            }
        };

        cache
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
