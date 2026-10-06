#compdef morsh

autoload -U is-at-least

_morsh() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'-p+[Override remote port (defaults to 2222 or port from destination / config)]:PORT:_default' \
'--port=[Override remote port (defaults to 2222 or port from destination / config)]:PORT:_default' \
'-i+[Path to SSH private key file (e.g. ~/.ssh/id_ed25519)]:IDENTITY:_files' \
'--identity=[Path to SSH private key file (e.g. ~/.ssh/id_ed25519)]:IDENTITY:_files' \
'-F+[Path to alternative client configuration file (defaults to ~/.morsh/config.toml)]:CONFIG:_files' \
'--config=[Path to alternative client configuration file (defaults to ~/.morsh/config.toml)]:CONFIG:_files' \
'*-o+[OpenSSH compatibility options in format Option=Value]:KEY=VALUE:_default' \
'*--option=[OpenSSH compatibility options in format Option=Value]:KEY=VALUE:_default' \
'--completions=[Generate shell completions for the specified shell (bash, zsh, fish) and exit]:SHELL:(bash elvish fish powershell zsh)' \
'--password=[Password for password / PAM authentication]:PASSWORD:_default' \
'-s+[TLS Server Name Indication (SNI) override]:SERVER_NAME:_default' \
'--server-name=[TLS Server Name Indication (SNI) override]:SERVER_NAME:_default' \
'--stealth-knock=[Optional stealth knock path prefix (SSH3 style anti-scanning defense)]:STEALTH_KNOCK:_default' \
'--tcp-fallback-timeout=[Happy Eyeballs TCP fallback threshold in milliseconds (default\: 300 ms)]:MS:_default' \
'*-L+[Local TCP port forwarding \[bind_addr\:\]bind_port\:target_host\:target_port (-L)]:SPEC:_default' \
'*--local-forward=[Local TCP port forwarding \[bind_addr\:\]bind_port\:target_host\:target_port (-L)]:SPEC:_default' \
'*-R+[Remote TCP port forwarding \[bind_addr\:\]bind_port\:target_host\:target_port (-R)]:SPEC:_default' \
'*--remote-forward=[Remote TCP port forwarding \[bind_addr\:\]bind_port\:target_host\:target_port (-R)]:SPEC:_default' \
'*-D+[Dynamic SOCKS5 proxy port \[bind_addr\:\]bind_port (-D)]:SPEC:_default' \
'*--dynamic-forward=[Dynamic SOCKS5 proxy port \[bind_addr\:\]bind_port (-D)]:SPEC:_default' \
'*-U+[Native UDP port forwarding \[bind_addr\:\]bind_port\:target_host\:target_port (-U)]:SPEC:_default' \
'*--udp-forward=[Native UDP port forwarding \[bind_addr\:\]bind_port\:target_host\:target_port (-U)]:SPEC:_default' \
'--resume=[Resume an existing detached persistent session by 128-bit session ID (hex string)]:SESSION_ID:_default' \
'--token=[Cryptographic 128-bit resumption token (hex string) for session resumption]:TOKEN:_default' \
'--ping=[Send N ping packets to measure round-trip latency over QUIC (0 starts interactive terminal session)]:PING:_default' \
'--predict=[Predictive local echo mode\: auto, always, or never]:MODE:_default' \
'--predict-style=[Predictive local echo visual style\: underline, dim, or none]:STYLE:_default' \
'-C[Request stream compression]' \
'--compress[Request stream compression]' \
'-4[Force IPv4 address resolution only]' \
'--ipv4[Force IPv4 address resolution only]' \
'-6[Force IPv6 address resolution only]' \
'--ipv6[Force IPv6 address resolution only]' \
'*-v[Increase verbosity level (-v\: info, -vv\: debug, -vvv\: trace)]' \
'*--verbose[Increase verbosity level (-v\: info, -vv\: debug, -vvv\: trace)]' \
'--man[Generate man page (roff format) to stdout and exit]' \
'--no-agent[Disable querying local ssh-agent (\$SSH_AUTH_SOCK)]' \
'-k[Accept any server certificate without validation (insecure / testing mode)]' \
'--insecure[Accept any server certificate without validation (insecure / testing mode)]' \
'--force-tcp[Force TLS 1.3 over TCP fallback (bypasses QUIC/UDP)]' \
'-N[Do not allocate an interactive PTY shell (tunnel-only mode)]' \
'--no-shell[Do not allocate an interactive PTY shell (tunnel-only mode)]' \
'--list-sessions[List active persistent sessions on the server and exit]' \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
'::destination -- Remote destination in format \[user@\]host\[\:port\]:_default' \
'*::command -- Optional command to execute on remote host:_default' \
&& ret=0
}

(( $+functions[_morsh_commands] )) ||
_morsh_commands() {
    local commands; commands=()
    _describe -t commands 'morsh commands' commands "$@"
}

if [ "$funcstack[1]" = "_morsh" ]; then
    _morsh "$@"
else
    compdef _morsh morsh
fi
