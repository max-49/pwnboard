# Vendored front-end libraries

These files are served by PWNBoard itself, so the web UI does not depend on a public CDN.
They are unmodified copies from jsDelivr.

| File | Library | Version | License | Source |
|------|---------|---------|---------|--------|
| `bootstrap.min.css` | Bootstrap | 4.6.2 | MIT | https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css |
| `bootstrap.min.js` | Bootstrap | 4.6.2 | MIT | https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.min.js |
| `popper.min.js` | Popper.js | 1.16.1 | MIT | https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js |
| `jquery.slim.min.js` | jQuery (slim build) | 3.7.1 | MIT | https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.slim.min.js |

Bootstrap 4.6.2 is the last 4.x release and needs jQuery 1.9.1 to 3.x and Popper.js ^1.16.1. Bootstrap 5
would be a migration (it drops jQuery and renames the `data-*` attributes and many classes), not a
drop-in upgrade.

To update one, download the new version from the same place and replace the file. Check it against
the package published on npm (for example `curl https://registry.npmjs.org/bootstrap/4.6.2` and compare
`dist.integrity` with the SHA-512 of the downloaded tarball, then compare the tarball's `dist/` file
with the one from jsDelivr). Then update the table above.
