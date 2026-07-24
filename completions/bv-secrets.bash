# Completion bash pour bv-secrets.
#   source completions/bv-secrets.bash
# ou copier dans /etc/bash_completion.d/ (ou ~/.local/share/bash-completion/completions/).
_bv_secrets_complete() {
    local IFS=$'\n'
    local out
    out=$(bv-secrets __complete "$COMP_CWORD" "${COMP_WORDS[@]}" 2>/dev/null)
    if [ -n "$out" ]; then
        COMPREPLY=( $out )
    else
        COMPREPLY=( $(compgen -f -- "${COMP_WORDS[COMP_CWORD]}") )   # fallback fichiers (scan/adopt)
    fi
}
complete -F _bv_secrets_complete bv-secrets
