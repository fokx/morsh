use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn morshd_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    // target/debug/deps/... -> target/debug/morshd
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("morshd")
}

fn morsh_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("morsh")
}

struct DaemonGuard {
    child: Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_cli_help_and_version() {
    let out = Command::new(morshd_bin())
        .arg("--help")
        .output()
        .expect("Failed to run morshd --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--completions"));
    assert!(stdout.contains("--man"));

    let out_client = Command::new(morsh_bin())
        .arg("--help")
        .output()
        .expect("Failed to run morsh --help");
    assert!(out_client.status.success());
    let client_stdout = String::from_utf8_lossy(&out_client.stdout);
    assert!(client_stdout.contains("-o, --option"));
    assert!(client_stdout.contains("-F, --config"));
    assert!(client_stdout.contains("-C, --compress"));
    assert!(client_stdout.contains("-4, --ipv4"));
    assert!(client_stdout.contains("-6, --ipv6"));
}

#[test]
fn test_shell_completions_output() {
    for shell in ["bash", "zsh", "fish"] {
        let out = Command::new(morsh_bin())
            .arg("--completions")
            .arg(shell)
            .output()
            .expect("Failed to run morsh completions");
        assert!(out.status.success());
        assert!(!out.stdout.is_empty());

        let out_d = Command::new(morshd_bin())
            .arg("--completions")
            .arg(shell)
            .output()
            .expect("Failed to run morshd completions");
        assert!(out_d.status.success());
        assert!(!out_d.stdout.is_empty());
    }
}

#[test]
fn test_man_pages_output() {
    let out = Command::new(morsh_bin())
        .arg("--man")
        .output()
        .expect("Failed to run morsh --man");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(".TH morsh 1"));

    let out_d = Command::new(morshd_bin())
        .arg("--man")
        .output()
        .expect("Failed to run morshd --man");
    assert!(out_d.status.success());
    let stdout_d = String::from_utf8_lossy(&out_d.stdout);
    assert!(stdout_d.contains(".TH morshd 8"));
}

#[test]
fn test_server_daemon_config_and_sighup_reload() {
    let port = get_free_port();
    let temp_dir = std::env::temp_dir().join(format!("morsh_test_{}", port));
    let _ = fs::create_dir_all(&temp_dir);
    let config_path = temp_dir.join("morshd.toml");

    // Write initial config with stealth knock v1
    let initial_toml = format!(
        r#"
listen = "127.0.0.1:{}"
tcp_listen = "127.0.0.1:{}"
stealth_knock = "/knock_v1"
no_auth = true
"#,
        port, port
    );
    fs::write(&config_path, initial_toml).unwrap();

    // Start morshd with the configuration file
    let child = Command::new(morshd_bin())
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start morshd daemon");

    let _guard = DaemonGuard { child };

    // Wait for server to bind
    std::thread::sleep(Duration::from_millis(300));

    // Connect with matching stealth knock v1 -> should succeed
    let status_v1 = Command::new(morsh_bin())
        .arg("-p")
        .arg(port.to_string())
        .arg("-k")
        .arg("--stealth-knock")
        .arg("/knock_v1")
        .arg("--ping")
        .arg("1")
        .arg("127.0.0.1")
        .status()
        .expect("Failed to execute morsh ping with v1 knock");
    assert!(status_v1.success(), "Initial knock /knock_v1 should succeed");

    // Connect with incorrect stealth knock v2 -> should fail (404 Not Found)
    let status_bad = Command::new(morsh_bin())
        .arg("-p")
        .arg(port.to_string())
        .arg("-k")
        .arg("--stealth-knock")
        .arg("/knock_v2")
        .arg("--ping")
        .arg("1")
        .arg("127.0.0.1")
        .status()
        .expect("Failed to execute morsh ping with wrong knock");
    assert!(!status_bad.success(), "Knock /knock_v2 should fail before reload");

    // Update config on disk to stealth_knock = "/knock_v2"
    let updated_toml = format!(
        r#"
listen = "127.0.0.1:{}"
tcp_listen = "127.0.0.1:{}"
stealth_knock = "/knock_v2"
no_auth = true
"#,
        port, port
    );
    fs::write(&config_path, updated_toml).unwrap();

    // Send SIGHUP to morshd
    #[cfg(unix)]
    {
        let kill_status = Command::new("kill")
            .arg("-HUP")
            .arg(_guard.child.id().to_string())
            .status()
            .expect("Failed to send SIGHUP via kill");
        assert!(kill_status.success());
    }

    // Wait for SIGHUP reload
    std::thread::sleep(Duration::from_millis(200));

    // Now connect with /knock_v2 -> should succeed!
    let status_v2 = Command::new(morsh_bin())
        .arg("-p")
        .arg(port.to_string())
        .arg("-k")
        .arg("--stealth-knock")
        .arg("/knock_v2")
        .arg("--ping")
        .arg("1")
        .arg("127.0.0.1")
        .status()
        .expect("Failed to execute morsh ping with v2 knock after reload");
    assert!(status_v2.success(), "Knock /knock_v2 should succeed after SIGHUP reload");

    // And /knock_v1 should now fail!
    let status_old = Command::new(morsh_bin())
        .arg("-p")
        .arg(port.to_string())
        .arg("-k")
        .arg("--stealth-knock")
        .arg("/knock_v1")
        .arg("--ping")
        .arg("1")
        .arg("127.0.0.1")
        .status()
        .expect("Failed to execute morsh ping with v1 knock after reload");
    assert!(!status_old.success(), "Old knock /knock_v1 should fail after SIGHUP reload");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_client_config_file_cascade() {
    let port = get_free_port();
    let temp_dir = std::env::temp_dir().join(format!("morsh_client_cfg_{}", port));
    let _ = fs::create_dir_all(&temp_dir);
    let client_config_path = temp_dir.join("config.toml");

    // Client config matching "my-server-alias" -> resolves port, user, knock, force_tcp
    let client_toml = format!(
        r#"
[[host]]
pattern = "my-server-alias"
host_name = "127.0.0.1"
port = {}
stealth_knock = "/custom-alias-knock"
force_tcp = true
insecure = true
"#,
        port
    );
    fs::write(&client_config_path, client_toml).unwrap();

    // Start server listening on that port with that knock
    let child = Command::new(morshd_bin())
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", port))
        .arg("--stealth-knock")
        .arg("/custom-alias-knock")
        .arg("--no-auth")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start morshd daemon");

    let _guard = DaemonGuard { child };
    std::thread::sleep(Duration::from_millis(300));

    // Connect using alias name and -F config file
    let status = Command::new(morsh_bin())
        .arg("-F")
        .arg(&client_config_path)
        .arg("--ping")
        .arg("1")
        .arg("my-server-alias")
        .status()
        .expect("Failed to run morsh with config file alias");

    assert!(status.success(), "Client config alias and knock should connect successfully");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_remote_command_execution() {
    let port = get_free_port();

    let child = Command::new(morshd_bin())
        .arg("--listen")
        .arg(format!("127.0.0.1:{}", port))
        .arg("--no-auth")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start morshd daemon");

    let _guard = DaemonGuard { child };
    std::thread::sleep(Duration::from_millis(300));

    let out = Command::new(morsh_bin())
        .arg("-p")
        .arg(port.to_string())
        .arg("-k")
        .arg("127.0.0.1")
        .arg("echo")
        .arg("HELLO_MORSH_EXEC")
        .stdin(Stdio::null())
        .output()
        .expect("Failed to execute remote command via morsh");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("HELLO_MORSH_EXEC"),
        "Output should contain execution result, got: {}",
        stdout
    );
}
