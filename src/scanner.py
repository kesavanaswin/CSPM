import subprocess
import json
import yaml
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

def run_opa(yaml_file):
    try:
        # Use full path to opa.exe if it exists in the current folder, otherwise fallback to "opa" in PATH
        opa_path = Path("opa.exe").resolve()
        if not opa_path.exists():
            cmd_executable = "opa"
        else:
            cmd_executable = str(opa_path)
        
        cmd = [
            cmd_executable, 
            "eval", 
            "--format", "json", 
            "-d", "policies", 
            "-i", str(yaml_file), 
            "data.main"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path.cwd())
        
        if result.returncode != 0:
            console.print(f"[red]OPA Command Failed:[/red]\n{result.stderr}")
            return None
            
        console.print("[dim]OPA Raw Output:[/dim]", result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
        
        return json.loads(result.stdout.strip())
        
    except FileNotFoundError:
        console.print("[red]Error: OPA executable not found! Make sure OPA is installed and in your PATH, or place opa.exe in the project folder.[/red]")
        return None
    except json.JSONDecodeError as e:
        console.print(f"[red]JSON Error: {e}[/red]\nRaw output: {result.stdout[:500]}")
        return None
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return None

def scan_config(file_path):
    console.print(f"[bold cyan]Scanning: {file_path}[/bold cyan]")
    result = run_opa(file_path)
    
    table = Table(title="Misconfiguration Report")
    table.add_column("Issue", style="red")
    table.add_column("Severity")
    
    has_violations = False
    if result and result.get("result"):
        for r in result.get("result", []):
            for expr in r.get("expressions", []):
                value = expr.get("value")
                if isinstance(value, dict):
                    for key, items in value.items():
                        if isinstance(items, list):
                            for msg in items:
                                table.add_row(str(msg), "HIGH")
                                has_violations = True
                elif isinstance(value, list):
                    for msg in value:
                        table.add_row(str(msg), "HIGH")
                        has_violations = True
    
    if has_violations:
        console.print(table)
    else:
        console.print("[green]No violations found or OPA failed.[/green]")

if __name__ == "__main__":
    scan_config("examples/bad-pod.yaml")