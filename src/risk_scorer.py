from rich.console import Console
from rich.table import Table

console = Console()

def calculate_risk(vuln_score, is_privileged, is_root, exposure):
    """
    Risk = Vulnerability × Exposure × Privilege
    """
    privilege_factor = 3.0 if is_privileged or is_root else 1.0
    exposure_factor = 2.5 if exposure == "high" else 1.5 if exposure == "medium" else 1.0
    
    risk_score = vuln_score * exposure_factor * privilege_factor
    
    if risk_score >= 80:
        level = "CRITICAL"
        color = "red"
    elif risk_score >= 50:
        level = "HIGH"
        color = "yellow"
    elif risk_score >= 20:
        level = "MEDIUM"
        color = "blue"
    else:
        level = "LOW"
        color = "green"
    
    return risk_score, level, color

def unified_risk_report(config_violations, vuln_count, image_name="nginx:latest"):
    console.print("\n[bold magenta]=== Unified Risk Analysis ===[/bold magenta]")
    
    # Simple logic: if many violations + high vulns = high risk
    has_privileged = any("privileged" in v.lower() for v in config_violations)
    has_root = any("root" in v.lower() for v in config_violations)
    
    vuln_score = min(vuln_count * 5, 100)  # Simple scoring
    
    risk_score, level, color = calculate_risk(
        vuln_score=vuln_score,
        is_privileged=has_privileged,
        is_root=has_root,
        exposure="high"   # Assume high for demo
    )
    
    table = Table(title="🎯 Unified Risk Score")
    table.add_column("Metric")
    table.add_column("Value")
    
    table.add_row("Image", image_name)
    table.add_row("Config Violations", str(len(config_violations)))
    table.add_row("High/Critical Vulns", str(vuln_count))
    table.add_row("Risk Score", f"{risk_score:.1f}/100", style=color)
    table.add_row("Risk Level", level, style=color)
    
    console.print(table)
    
    if level in ["CRITICAL", "HIGH"]:
        console.print(f"[bold red]Recommendation: Do NOT deploy this container![/bold red]")

# Example usage
if __name__ == "__main__":
    violations = [
        "Privileged container is dangerous!",
        "Running as root!",
        "Missing resource limits"
    ]
    unified_risk_report(violations, 65)