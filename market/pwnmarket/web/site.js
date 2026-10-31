"use strict";
// Shared by every page: remembers and switches the light/dark theme.
function store(key, value) { try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (e) { return null; } }
function applyTheme(t) { if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; }
applyTheme(store("pwnmarket-theme"));
document.getElementById("theme").onclick = () => {
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  const now = document.documentElement.dataset.theme || (dark ? "dark" : "light");
  const next = now === "dark" ? "light" : "dark";
  applyTheme(next); store("pwnmarket-theme", next);
};

