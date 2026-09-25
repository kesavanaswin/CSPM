import subprocess
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

def run_trivy(image_name):
    console.print(f"[bold cyan]Scanning image: {image_name}[/bold cyan]")
    
    try:
        # Run Trivy and save result as JSON
        output_file = Path("outputs") / "trivy_result.json"
        output_file.parent.mkdir(exist_ok=True)
        
        result = subprocess.run([
            "trivy", "image",
            "--format", "json",
            "--output", str(output_file),
            "--severity", "HIGH,CRITICAL",
            image_name
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            console.print(f"[yellow]Trivy Warning: {result.stderr}[/yellow]")
        
        # Read the result
        with open(output_file, encoding='utf-8') as f:
            data = json.load(f)
        
        return data
        
    except FileNotFoundError:
        console.print("[red]❌ trivy.exe not found! Put trivy.exe in project folder.[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return None

def print_vuln_report(data, image_name):
    if not data or "Results" not in data:
        console.print("[green]No critical vulnerabilities found.[/green]")
        return
    
    table = Table(title=f"🚨 Vulnerabilities in {image_name}")
    table.add_column("Package", style="cyan")
    table.add_column("Vulnerability", style="red")
    table.add_column("Severity", style="yellow")
    table.add_column("Fixed Version")
    
    count = 0
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            if vuln.get("Severity") in ["HIGH", "CRITICAL"]:
                table.add_row(
                    vuln.get("PkgName", "N/A"),
                    vuln.get("VulnerabilityID", "N/A"),
                    vuln.get("Severity", "N/A"),
                    vuln.get("FixedVersion", "None")
                )
                count += 1
    
    console.print(table)
    console.print(f"[bold red]Total High/Critical Vulnerabilities: {count}[/bold red]")

if __name__ == "__main__":
    image = "nginx:latest"   # Change this to any image
    data = run_trivy(image)
    if data:
        print_vuln_report(data, image)