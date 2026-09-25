package cspm.resource_limits

violation[msg] {
    input.resource_limits_set == false
    msg := "Container has no CPU/memory resource limits set"
}
