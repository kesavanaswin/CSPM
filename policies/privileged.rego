package cspm.privileged

# Deny/flag containers running in privileged mode
violation[msg] {
    input.privileged == true
    msg := "Container is running in privileged mode"
}

# Deny/flag containers running as root
violation[msg] {
    input.runAsRoot == true
    msg := "Container is running as root user"
}
