complete -c morshd -s l -l listen -d 'Socket address to listen on for incoming UDP/QUIC traffic (default: 0.0.0.0:2222)' -r
complete -c morshd -l tcp-listen -d 'Optional explicit socket address to listen on for TCP fallback (defaults to same port as --listen)' -r
complete -c morshd -s C -l config -d 'Optional path to server TOML configuration file (defaults to /etc/morsh/morshd.toml)' -r -F
complete -c morshd -l completions -d 'Generate shell completions for the specified shell (bash, zsh, fish) and exit' -r -f -a "bash\t''
elvish\t''
fish\t''
powershell\t''
zsh\t''"
complete -c morshd -s c -l cert -d 'Optional path to TLS certificate chain in PEM format' -r -F
complete -c morshd -s k -l key -d 'Optional path to TLS private key in PEM format (PKCS#8)' -r -F
complete -c morshd -l stealth-knock -d 'Optional stealth knock path prefix (SSH3 style anti-scanning defense)' -r
complete -c morshd -l auth-keys -d 'Optional explicit path to authorized_keys file (defaults to ~/.ssh/authorized_keys per user)' -r -F
complete -c morshd -l pam-service -d 'PAM service name to use for password authentication (default: morsh)' -r
complete -c morshd -l man -d 'Generate man page (roff format) to stdout and exit'
complete -c morshd -l allow-password -d 'Allow Linux PAM / password authentication'
complete -c morshd -l no-auth -d 'Permit unauthenticated connections (testing / development only)'
complete -c morshd -s v -l verbose -d 'Enable verbose debug logging'
complete -c morshd -s h -l help -d 'Print help'
complete -c morshd -s V -l version -d 'Print version'
