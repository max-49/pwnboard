#!/usr/bin/env python3
"""Interactive quick setup for PWNBoard.

Combines the README Quick Start steps into one workflow:
1) Configure .env (SECRET_KEY and PWNBOARD_PASSWORD)
2) Generate board.json via scripts/gen_config.py
3) Generate HTTPS certificates (self-signed or Let's Encrypt)

This script is intentionally interactive and prompts before overwriting files.
"""

from __future__ import annotations

import os
import re
import shutil
import secrets
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
ENV_PATH = ROOT / ".env"
BOARD_PATH = ROOT / "board.json"
DOCKER_COMPOSE_PATH = ROOT / "docker-compose.yml"
CERT_PATH = ROOT / "conf" / "cert.pem"
KEY_PATH = ROOT / "conf" / "key.pem"


def prompt_yes_no(message: str, default: bool = True) -> bool:
	suffix = " [Y/n]: " if default else " [y/N]: "
	while True:
		raw = input(message + suffix).strip().lower()
		if raw == "":
			return default
		if raw in {"y", "yes"}:
			return True
		if raw in {"n", "no"}:
			return False
		print("Please answer yes or no.")


def prompt_text(message: str, default: str | None = None, allow_empty: bool = False) -> str:
	while True:
		if default is None:
			raw = input(f"{message}: ").strip()
		else:
			raw = input(f"{message} [{default}]: ").strip()
			if raw == "":
				raw = default
		if raw or allow_empty:
			return raw
		print("A value is required.")


def parse_domain_from_url(url: str) -> str:
	url = (url or "").strip()
	url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
	return url.split("/")[0].strip()


def command_exists(name: str) -> bool:
	return shutil.which(name) is not None


def should_overwrite(path: Path) -> bool:
	if not path.exists():
		return True
	return prompt_yes_no(f"{path} already exists. Overwrite", default=False)


def read_env(path: Path) -> dict[str, str]:
	env_map: dict[str, str] = {}
	if not path.exists():
		return env_map
	for line in path.read_text(encoding="utf-8").splitlines():
		line = line.strip()
		if not line or line.startswith("#") or "=" not in line:
			continue
		k, v = line.split("=", 1)
		env_map[k.strip()] = v.strip()
	return env_map


def upsert_env_values(path: Path, updates: dict[str, str]) -> None:
	original_lines: list[str] = []
	if path.exists():
		original_lines = path.read_text(encoding="utf-8").splitlines()

	replaced: set[str] = set()
	new_lines: list[str] = []
	for line in original_lines:
		stripped = line.strip()
		if not stripped or stripped.startswith("#") or "=" not in line:
			new_lines.append(line)
			continue
		key = line.split("=", 1)[0].strip()
		if key in updates:
			new_lines.append(f"{key}={updates[key]}")
			replaced.add(key)
		else:
			new_lines.append(line)

	for key, value in updates.items():
		if key not in replaced:
			new_lines.append(f"{key}={value}")

	path.write_text("\n".join(new_lines).rstrip() + "\n", encoding="utf-8")


def update_pwnboard_url_in_compose(url: str) -> bool:
	if not DOCKER_COMPOSE_PATH.exists():
		print(f"Skipping docker-compose URL update: missing {DOCKER_COMPOSE_PATH}")
		return False

	text = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
	pattern = re.compile(r"(^\s*-\s*PWNBOARD_URL=).*$", flags=re.MULTILINE)
	if not pattern.search(text):
		print("Did not find PWNBOARD_URL line in docker-compose.yml")
		return False

	updated = pattern.sub(rf"\1{url}", text, count=1)
	DOCKER_COMPOSE_PATH.write_text(updated, encoding="utf-8")
	return True


def configure_env() -> tuple[str, str]:
	print("\n=== Environment Setup (.env) ===")
	if ENV_PATH.exists() and not prompt_yes_no(
		f"{ENV_PATH} already exists. Update secret/password values",
		default=True,
	):
		existing = read_env(ENV_PATH)
		password = existing.get("PWNBOARD_PASSWORD", "password")
		secret_key = existing.get("SECRET_KEY", "change-me-please")
		print("Keeping existing .env values.")
		return password, secret_key

	existing = read_env(ENV_PATH)
	default_password = existing.get("PWNBOARD_PASSWORD", "password")
	password = prompt_text("PWNBOARD_PASSWORD", default=default_password)

	default_secret = existing.get("SECRET_KEY", "")
	if not default_secret or default_secret == "change-me-please":
		default_secret = secrets.token_urlsafe(48)

	if prompt_yes_no("Generate a random SECRET_KEY", default=True):
		secret_key = secrets.token_urlsafe(48)
	else:
		secret_key = prompt_text("SECRET_KEY", default=default_secret)

	upsert_env_values(
		ENV_PATH,
		{
			"PWNBOARD_PASSWORD": password,
			"SECRET_KEY": secret_key,
		},
	)
	print(f"Updated {ENV_PATH}")
	return password, secret_key


def configure_board() -> None:
	print("\n=== Board Setup (board.json) ===")
	if not should_overwrite(BOARD_PATH):
		print("Keeping existing board.json")
		return

	gen_script = SCRIPTS_DIR / "gen_config.py"
	if not gen_script.exists():
		print(f"Cannot find generator: {gen_script}")
		return

	print("Launching interactive board generator...")
	proc = subprocess.run([sys.executable, str(gen_script)], cwd=str(ROOT))
	if proc.returncode != 0:
		raise RuntimeError("Board generation failed.")
	print(f"Generated {BOARD_PATH}")


def generate_self_signed_cert(domain: str) -> None:
	if not command_exists("openssl"):
		raise RuntimeError("openssl was not found in PATH.")

	CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
	cmd = [
		"openssl",
		"req",
		"-x509",
		"-nodes",
		"-days",
		"365",
		"-newkey",
		"rsa:2048",
		"-keyout",
		str(KEY_PATH),
		"-out",
		str(CERT_PATH),
		"-subj",
		f"/C=US/ST=State/L=Town/O=PWNBoard/OU=Deployment/CN={domain}",
	]
	subprocess.run(cmd, check=True)

	if os.name != "nt":
		try:
			KEY_PATH.chmod(0o644)
			CERT_PATH.chmod(0o644)
		except Exception:
			pass


def generate_letsencrypt_cert(domain: str, email: str) -> None:
	if not command_exists("certbot"):
		raise RuntimeError("certbot was not found in PATH.")

	certbot_cmd = [
		"certbot",
		"certonly",
		"--manual",
		"--preferred-challenges",
		"dns",
		"-d",
		domain,
		"--agree-tos",
		"--email",
		email,
	]
	print("Running certbot (interactive DNS challenge)...")
	subprocess.run(certbot_cmd, check=True)

	live_dir = Path(f"/etc/letsencrypt/live/{domain}")
	archive_dir = Path(f"/etc/letsencrypt/archive/{domain}")

	cert_source_candidates = [
		live_dir / "fullchain.pem",
		archive_dir / "fullchain1.pem",
	]
	key_source_candidates = [
		live_dir / "privkey.pem",
		archive_dir / "privkey1.pem",
	]

	cert_source = next((p for p in cert_source_candidates if p.exists()), None)
	key_source = next((p for p in key_source_candidates if p.exists()), None)

	if not cert_source or not key_source:
		raise RuntimeError(
			"Could not locate Let's Encrypt cert/key files after certbot run."
		)

	CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
	shutil.copy2(cert_source, CERT_PATH)
	shutil.copy2(key_source, KEY_PATH)

	if os.name != "nt":
		try:
			KEY_PATH.chmod(0o644)
			CERT_PATH.chmod(0o644)
		except Exception:
			pass


def configure_certificates(pwnboard_url: str) -> None:
	print("\n=== Certificate Setup (conf/cert.pem + conf/key.pem) ===")
	if CERT_PATH.exists() or KEY_PATH.exists():
		if not prompt_yes_no(
			"Certificate files already exist. Overwrite cert.pem/key.pem",
			default=False,
		):
			print("Keeping existing certificate files.")
			return

	mode = prompt_text(
		"Certificate mode: self-signed / letsencrypt / skip",
		default="self-signed",
	).strip().lower()

	if mode in {"skip", "none", "no"}:
		print("Skipping certificate generation.")
		return

	domain_default = parse_domain_from_url(pwnboard_url) or "127.0.0.1"
	domain = prompt_text("Domain/IP for certificate CN", default=domain_default)

	if mode in {"self", "self-signed", "selfsigned"}:
		generate_self_signed_cert(domain)
		print(f"Created {CERT_PATH} and {KEY_PATH}")
		return

	if mode in {"letsencrypt", "le"}:
		if os.name == "nt":
			raise RuntimeError("Let's Encrypt automation via certbot is not supported on Windows in this script.")
		email = prompt_text("Let's Encrypt email", default=f"admin@{domain}")
		generate_letsencrypt_cert(domain, email)
		print(f"Created {CERT_PATH} and {KEY_PATH}")
		return

	print(f"Unknown certificate mode: {mode}. Skipping.")


def configure_compose_url() -> str:
	print("\n=== docker-compose URL Setup ===")
	current_default = "https://127.0.0.1"
	if DOCKER_COMPOSE_PATH.exists():
		text = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
		m = re.search(r"^\s*-\s*PWNBOARD_URL=(.+)$", text, flags=re.MULTILINE)
		if m:
			current_default = m.group(1).strip()

	url = prompt_text("PWNBOARD_URL", default=current_default)
	if prompt_yes_no("Update PWNBOARD_URL in docker-compose.yml", default=True):
		if update_pwnboard_url_in_compose(url):
			print("Updated PWNBOARD_URL in docker-compose.yml")
	return url


def main() -> int:
	print("PWNBoard Quick Setup")
	print(f"Project root: {ROOT}\n")

	try:
		configure_env()
		configure_board()
		pwnboard_url = configure_compose_url()
		configure_certificates(pwnboard_url)
	except KeyboardInterrupt:
		print("\nSetup cancelled.")
		return 130
	except subprocess.CalledProcessError as exc:
		print(f"\nCommand failed with exit code {exc.returncode}: {exc.cmd}")
		return exc.returncode or 1
	except Exception as exc:
		print(f"\nSetup failed: {exc}")
		return 1

	print("\nSetup complete. Next step: docker compose up -d")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
