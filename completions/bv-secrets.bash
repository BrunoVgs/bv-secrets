# Completion bash pour bv-secrets.
#   source completions/bv-secrets.bash
# ou copier dans /etc/bash_completion.d/ (ou ~/.local/share/bash-completion/completions/).
_bv_secrets_complete() {
    local IFS=$'\n'
    COMPREPLY=( $(bv-secrets __complete "$COMP_CWORD" "${COMP_WORDS[@]}" 2>/dev/null) )
}
complete -F _bv_secrets_complete bv-secrets
