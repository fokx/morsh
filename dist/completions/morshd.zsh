#compdef morshd

autoload -U is-at-least

_morshd() {
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
'-l+[Socket address to listen on for incoming UDP/QUIC traffic (default\: 0.0.0.0\:2222)]:LISTEN:_default' \
'--listen=[Socket address to listen on for incoming UDP/QUIC traffic (default\: 0.0.0.0\:2222)]:LISTEN:_default' \
'--tcp-listen=[Optional explicit socket address to listen on for TCP fallback (defaults to same port as --listen)]:TCP_LISTEN:_default' \
'-C+[Optional path to server TOML configuration file (defaults to /etc/morsh/morshd.toml)]:CONFIG:_files' \
'--config=[Optional path to server TOML configuration file (defaults to /etc/morsh/morshd.toml)]:CONFIG:_files' \
'--completions=[Generate shell completions for the specified shell (bash, zsh, fish) and exit]:SHELL:(bash elvish fish powershell zsh)' \
'-c+[Optional path to TLS certificate chain in PEM format]:CERT:_files' \
'--cert=[Optional path to TLS certificate chain in PEM format]:CERT:_files' \
'-k+[Optional path to TLS private key in PEM format (PKCS#8)]:KEY:_files' \
'--key=[Optional path to TLS private key in PEM format (PKCS#8)]:KEY:_files' \
'--stealth-knock=[Optional stealth knock path prefix (SSH3 style anti-scanning defense)]:STEALTH_KNOCK:_default' \
'--auth-keys=[Optional explicit path to authorized_keys file (defaults to ~/.ssh/authorized_keys per user)]:AUTH_KEYS:_files' \
'--pam-service=[PAM service name to use for password authentication (default\: morsh)]:PAM_SERVICE:_default' \
'--man[Generate man page (roff format) to stdout and exit]' \
'--allow-password[Allow Linux PAM / password authentication]' \
'--no-auth[Permit unauthenticated connections (testing / development only)]' \
'-v[Enable verbose debug logging]' \
'--verbose[Enable verbose debug logging]' \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
&& ret=0
}

(( $+functions[_morshd_commands] )) ||
_morshd_commands() {
    local commands; commands=()
    _describe -t commands 'morshd commands' commands "$@"
}

if [ "$funcstack[1]" = "_morshd" ]; then
    _morshd "$@"
else
    compdef _morshd morshd
fi
