//! Real ssh-forwarding proof for the ssh-transport lane's P-S3 phase (the
//! ssh child owned by `aoide_client::tunnel`) — the `peer_connectivity.rs`
//! precedent (that file's own module doc, lines 24-33): a genuine `ssh -N
//! -L` forward to `localhost`, carrying real bytes through a real
//! throwaway TCP listener, never a mock.
//!
//! `#[ignore]`'d, not skipped: this shells out to a REAL `ssh`, which needs
//! `ssh` on `PATH`, real loopback networking, AND this box's own public key
//! already present in its own `~/.ssh/authorized_keys` (`BatchMode=yes`
//! means a missing key fails fast rather than prompting — see
//! `crates/client/src/tunnel.rs`'s module doc). None of that holds inside
//! the nix package build's sandboxed `checkPhase`. Run explicitly:
//!   cargo test -p aoide-cli --test tunnel_ssh -- --ignored
//! in a dev shell that has both `ssh` and real networking.

use aoide_storage::tunnel::Via;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[test]
#[ignore = "real ssh to localhost — needs this box's own key in its own authorized_keys; run with --ignored"]
fn open_or_reuse_forwards_real_bytes_to_a_local_throwaway_listener_over_real_ssh() {
    let root = std::env::temp_dir().join(format!("aoide-tunnel-ssh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::env::set_var("XDG_RUNTIME_DIR", &root);

    // A throwaway TCP listener standing in for a peer's real A2A door —
    // echoes back whatever it reads, so the assertion below proves bytes
    // actually crossed the ssh forward, not merely that a TCP connect
    // succeeded.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                let _ = stream.write_all(&buf[..n]);
            }
        }
    });

    let via = Via { user: None, host: "localhost".to_string(), port: None };
    let local_port = aoide_client::tunnel::open_or_reuse(
        "tunnel-ssh-test",
        "localhost",
        &via,
        "127.0.0.1",
        remote_port,
    )
    .expect("ssh tunnel to localhost must open — is this box's own key in its own authorized_keys?");

    let mut stream = TcpStream::connect(("127.0.0.1", local_port)).unwrap();
    stream.write_all(b"ping").unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping", "bytes must round-trip through the real ssh -L forward");

    // A second call for the same (session, key) reuses the already-open
    // forward rather than spawning a second `ssh` — `pgrep -af 'ssh -N'`
    // by hand should show exactly one.
    let reused_port = aoide_client::tunnel::open_or_reuse(
        "tunnel-ssh-test",
        "localhost",
        &via,
        "127.0.0.1",
        remote_port,
    )
    .unwrap();
    assert_eq!(reused_port, local_port, "the second open must reuse the same forward");

    aoide_client::tunnel::close("tunnel-ssh-test", "localhost").unwrap();

    let _ = std::fs::remove_dir_all(&root);
    std::env::remove_var("XDG_RUNTIME_DIR");
}
