package cspm.container

# Deny privileged containers
deny[msg] {
    input.spec.containers[_].securityContext.privileged == true
    msg := "Container is running in privileged mode"
}

# Deny containers running as root (uid 0)
deny[msg] {
    c := input.spec.containers[_]
    c.securityContext.runAsUser == 0
    msg := sprintf("Container '%s' is explicitly running as root (uid 0)", [c.name])
}

# Deny missing runAsNonRoot when no runAsUser is set at all
deny[msg] {
    c := input.spec.containers[_]
    not c.securityContext.runAsUser
    not c.securityContext.runAsNonRoot
    msg := sprintf("Container '%s' does not enforce a non-root user", [c.name])
}

# Deny containers with no CPU/memory limits set
deny[msg] {
    c := input.spec.containers[_]
    not c.resources.limits.cpu
    msg := sprintf("Container '%s' has no CPU resource limit set", [c.name])
}

deny[msg] {
    c := input.spec.containers[_]
    not c.resources.limits.memory
    msg := sprintf("Container '%s' has no memory resource limit set", [c.name])
}

# Deny use of host namespaces
deny[msg] {
    input.spec.hostNetwork == true
    msg := "Pod uses hostNetwork: true, exposing it to the host's network namespace"
}

deny[msg] {
    input.spec.hostPID == true
    msg := "Pod uses hostPID: true, exposing it to host process visibility"
}

# Deny mounting the Docker socket
deny[msg] {
    v := input.spec.volumes[_]
    v.hostPath.path == "/var/run/docker.sock"
    msg := "Pod mounts the Docker socket from the host, a common privilege-escalation path"
}
