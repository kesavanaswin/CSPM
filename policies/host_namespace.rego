package cspm.host_namespace

violation[msg] {
    input.hostNetwork == true
    msg := "Container shares the host network namespace (hostNetwork=true)"
}

violation[msg] {
    input.hostPID == true
    msg := "Container shares the host PID namespace (hostPID=true)"
}
