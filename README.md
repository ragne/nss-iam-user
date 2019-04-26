Skeleton of nss-iam-user module
====

Build && install
================
  USE A VM!

 - `cargo build --release`
 - `cp target/release/libnss_iam_user.so /usr/lib/libnss_iam_user.so.2`
 - optionally `ldconfig -n`
 - edit `/etc/nsswitch.conf`: `passwd:         compat iam_user systemd`