complete -c morsh -s p -l port -d 'Override remote port (defaults to 2222 or port from destination / config)' -r
complete -c morsh -s i -l identity -d 'Path to SSH private key file (e.g. ~/.ssh/id_ed25519)' -r -F
complete -c morsh -s F -l config -d 'Path to alternative client configuration file (defaults to ~/.morsh/config.toml)' -r -F
complete -c morsh -s o -l option -d 'OpenSSH compatibility options in format Option=Value' -r
complete -c morsh -l completions -d 'Generate shell completions for the specified shell (bash, zsh, fish) and exit' -r -f -a "bash\t''
elvish\t''
fish\t''
powershell\t''
zsh\t''"
complete -c morsh -l password -d 'Password for password / PAM authentication' -r
complete -c morsh -s s -l server-name -d 'TLS Server Name Indication (SNI) override' -r
complete -c morsh -l stealth-knock -d 'Optional stealth knock path prefix (SSH3 style anti-scanning defense)' -r
complete -c morsh -l tcp-fallback-timeout -d 'Happy Eyeballs TCP fallback threshold in milliseconds (default: 300 ms)' -r
complete -c morsh -s L -l local-forward -d 'Local TCP port forwarding [bind_addr:]bind_port:target_host:target_port (-L)' -r
complete -c morsh -s R -l remote-forward -d 'Remote TCP port forwarding [bind_addr:]bind_port:target_host:target_port (-R)' -r
complete -c morsh -s D -l dynamic-forward -d 'Dynamic SOCKS5 proxy port [bind_addr:]bind_port (-D)' -r
complete -c morsh -s U -l udp-forward -d 'Native UDP port forwarding [bind_addr:]bind_port:target_host:target_port (-U)' -r
complete -c morsh -l resume -d 'Resume an existing detached persistent session by 128-bit session ID (hex string)' -r
complete -c morsh -l token -d 'Cryptographic 128-bit resumption token (hex string) for session resumption' -r
complete -c morsh -l ping -d 'Send N ping packets to measure round-trip latency over QUIC (0 starts interactive terminal session)' -r
complete -c morsh -l predict -d 'Predictive local echo mode: auto, always, or never' -r
complete -c morsh -l predict-style -d 'Predictive local echo visual style: underline, dim, or none' -r
complete -c morsh -s C -l compress -d 'Request stream compression'
complete -c morsh -s 4 -l ipv4 -d 'Force IPv4 address resolution only'
complete -c morsh -s 6 -l ipv6 -d 'Force IPv6 address resolution only'
complete -c morsh -s v -l verbose -d 'Increase verbosity level (-v: info, -vv: debug, -vvv: trace)'
complete -c morsh -l man -d 'Generate man page (roff format) to stdout and exit'
complete -c morsh -l no-agent -d 'Disable querying local ssh-agent ($SSH_AUTH_SOCK)'
complete -c morsh -s k -l insecure -d 'Accept any server certificate without validation (insecure / testing mode)'
complete -c morsh -l force-tcp -d 'Force TLS 1.3 over TCP fallback (bypasses QUIC/UDP)'
complete -c morsh -s N -l no-shell -d 'Do not allocate an interactive PTY shell (tunnel-only mode)'
complete -c morsh -l list-sessions -d 'List active persistent sessions on the server and exit'
complete -c morsh -s h -l help -d 'Print help'
complete -c morsh -s V -l version -d 'Print version'
