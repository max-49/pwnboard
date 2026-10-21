#!/usr/bin/env python3
"""Interactive quick setup for PWNBoard.

Combines the README Quick Start steps into one workflow:
1) Configure .env (PWNBOARD_DOMAIN, PWNBOARD_PASSWORD and SECRET_KEY)
2) Generate board.json via scripts/gen_config.py

HTTPS certificates are handled by Caddy, so none are generated here.

This script is intentionally interactive and prompts before overwriting files.
"""

from __future__ import annotations

import re
import secrets
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
ENV_PATH = ROOT / ".env"
BOARD_PATH = ROOT / "board.json"

# Variables docker-compose.yml expects in .env
ENV_KEYS = {"PWNBOARD_DOMAIN", "PWNBOARD_PASSWORD", "SECRET_KEY"}


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


def configure_env() -> None:
	print("\n=== Environment Setup (.env) ===")
	existing = read_env(ENV_PATH)
	if ENV_KEYS <= existing.keys() and not prompt_yes_no(
		f"{ENV_PATH} already exists. Update domain/secret/password values",
		default=True,
	):
		print("Keeping existing .env values.")
		return

	print("Public domain: Caddy gets a Let's Encrypt certificate automatically (ports 80 and 443 must be reachable).")
	print("localhost or an IP address: Caddy uses its own internal CA, so clients must skip certificate validation (e.g. curl -k).")
	domain = parse_domain_from_url(
		prompt_text("PWNBOARD_DOMAIN", default=existing.get("PWNBOARD_DOMAIN", "localhost"))
	)

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
			"PWNBOARD_DOMAIN": domain,
			"PWNBOARD_PASSWORD": password,
			"SECRET_KEY": secret_key,
			# Password of the read-only database user Grafana connects with. Keep an existing one.
			"GRAFANA_DB_PASSWORD": existing.get("GRAFANA_DB_PASSWORD") or secrets.token_urlsafe(24),
		},
	)
	print(f"Updated {ENV_PATH}")


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


def main() -> int:
	print("PWNBoard Quick Setup")
	print(f"Project root: {ROOT}\n")

	try:
		configure_env()
		configure_board()
	except KeyboardInterrupt:
		print("\nSetup canceled.")
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
