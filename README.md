NSS IAM module
====

*Do not use in production* 

This module can be used as proxy between AWS IAM and standard *NIX users.
It works by enumerating all IAM Users and converting them to appropriate *NIX users on the fly (when some program asks for user detail, via e.g getpwnam_r).
To speed up the process file cache is build on the machine to store all user-related data for 10(now hardcoded) minutes.

Written in Rust (because I don't know C++ well enough and C lacks any AWS-sdk libraries).

Intended Usage
======

Indended to be used to allow privileged third-party access to machines in AWS account without granting AWS Console rights. It allows more control than just one shared ssh key, because you can delete ssh key from IAM user to revoke the access. Thus some choices that were made wouldn't work when higher security is a requirement. 


Current abilities
=================

 - Allow to authenticate using IAM username and ssh-key 
 - Automatically adds ssh-keys from IAM user profile to machine on first login
 - Caching of users for next 10 minutes
 - Automatically adds user to `sudo`/`wheel` group


Build && install
================

## Building 

To build that you need the same (or less than) version of `libc` than on target system, so the easiest way is to build 
directly on target machine. You'll need rust compiler for that. [Here](https://rustup.rs/) is the link.

Then `cargo build --release` in project directory should do the trick.

## Installation

*NOTE:* Correct IAM policy should be in place for machine's InstanceProfile. Actions being used:
```yaml
  - "iam:ListSSHPublicKeys"
  - "iam:ListGroupsForUser"
  - "iam:GetSSHPublicKey"
  - "iam:ListUsers"
  - "iam:ListGroups"
  - "iam:GetUser"
  - "iam:GetGroup"
  - "iam:ListUserTags"
```

To install you have to copy `target/release/libnss_iam_user.so` into OS `lib` directory, typically `/lib64` or `/usr/lib`, consult your distro docs for that. And create appropriate symlink so NSS can detect the module (`libnss_iam_user.so` -> `libnss_iam_user.so.2`)

Then edit `/etc/nsswitch.conf` and add `iam_user` as last entry to `passwd` and `group` categories, like that:
```
passwd:         compat systemd iam_user
```

To test try executing `getent passwd $USERNAME` with your IAM username, it should return something

Caveats
====

 - Slowness: permission related, to create cache file library needs `root` permissions. 
 - Hardcode: currently lacking config file, so all value are hardcoded in code (like timeouts, basic region for IAM and others)
 - Adds user to `sudo` if users log in through `sshd` (compare program name with string `sshd`).

## Security

 - Currently malicious actor could rewrite the cache file with it's own ssh-key and get an privileged access
 - In theory using symlinks one can trigger adding user from IAM to sudo group, but that's won't be fatal, because login is only possible by using ssh-key.
 And adding user to sudo is _the intent_ of the library.
