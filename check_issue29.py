import subprocess
import sys

def install_package(package):
    subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)

def is_typosquatting_suspicious(package_name):
    return any(p in package_name.lower() for p in ("reqeusts", "urllib3-", "crypt0", "pycryptodome-", "django-", "flask-"))

def verify_requirements_file(file_path):
    for raw in open(file_path, encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        if line.startswith(("http://", "https://")): return False
        package = line.split("==")[0].split(">=")[0].split("<=")[0].split("!=")[0].strip()
        if is_typosquatting_suspicious(package): return False
    return True

def install_requirements(file_path):
    if not verify_requirements_file(file_path): raise SystemExit("Requirements file verification failed")
    for raw in open(file_path, encoding="utf-8"):
        package = raw.strip()
        if package and not package.startswith("#"): install_package(package)

if __name__ == "__main__" and len(sys.argv) > 1: install_requirements(sys.argv[1])
