"""Bootstrap installer for this project.

Usage (Windows PowerShell):
  python setup.py

This script:
  1) Creates a virtual environment in .venv (if missing)
  2) Upgrades pip tooling
  3) Installs dependencies from requirements.txt

Note: This is intentionally a bootstrap helper, not a packaging setup.py.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import venv


def _run(cmd: list[str], *, cwd: Path) -> None:
    subprocess.run(cmd, cwd=str(cwd), check=True)


def _venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def ensure_venv(venv_dir: Path) -> Path:
    py = _venv_python(venv_dir)
    if py.exists():
        return py

    print(f"[setup] Creating venv: {venv_dir}")
    venv.EnvBuilder(with_pip=True).create(str(venv_dir))

    py = _venv_python(venv_dir)
    if not py.exists():
        raise RuntimeError(f"venv created but python not found at: {py}")
    return py


def install_requirements(py: Path, *, project_root: Path, requirements: Path) -> None:
    print("[setup] Upgrading pip/setuptools/wheel")
    _run([str(py), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], cwd=project_root)

    print(f"[setup] Installing dependencies from {requirements.name}")
    _run([str(py), "-m", "pip", "install", "-r", str(requirements)], cwd=project_root)


def main() -> int:
    project_root = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description="Create venv and install prerequisites")
    parser.add_argument("--venv", default=str(project_root / ".venv"), help="Virtual environment directory")
    parser.add_argument("--requirements", default=str(project_root / "requirements.txt"), help="Requirements file")
    args = parser.parse_args()

    venv_dir = Path(args.venv)
    requirements = Path(args.requirements)

    if not requirements.exists():
        print(f"[setup] ERROR: requirements file not found: {requirements}")
        return 2

    try:
        py = ensure_venv(venv_dir)
        install_requirements(py, project_root=project_root, requirements=requirements)
    except subprocess.CalledProcessError as exc:
        print(f"[setup] ERROR: command failed with exit code {exc.returncode}")
        return exc.returncode
    except Exception as exc:
        print(f"[setup] ERROR: {exc}")
        return 1

    print("\n[setup] Done.")
    if os.name == "nt":
        print(f"Next:\n  {venv_dir}\\Scripts\\Activate.ps1\n  python run.py")
    else:
        print(f"Next:\n  source {venv_dir}/bin/activate\n  python run.py")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
