package main

deny contains msg if {
    input.spec.containers[_].securityContext.privileged == true
    msg := "Privileged container is dangerous!"
}

deny contains msg if {
    input.spec.containers[_].securityContext.runAsUser == 0
    msg := "Running as root!"
}

deny contains msg if {
    container := input.spec.containers[_]
    not container.resources.limits
    msg := "Missing resource limits"
}