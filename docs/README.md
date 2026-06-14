# LWRT Documentation

The documentation site for **LWRT** — OpenWrt's userspace reimagined as one
compact static Rust binary, riding inside an execute-in-place (XIP) Linux
kernel.

## Local Development

No build step required. The documentation is a static HTML site:

```bash
# Open in browser
open docs/index.html

# Or serve with Python
cd docs
python3 -m http.server 8000
# Visit http://localhost:8000
```

## GitHub Pages Deployment

The site is served from the `docs/` directory on the main branch.

## File Structure

```
docs/
├── index.html      # Main documentation page
├── style.css       # Stylesheet
├── script.js       # Interactive features (nav, search, copy buttons)
├── _config.yml     # GitHub Pages configuration
├── .nojekyll       # Bypass Jekyll processing
└── README.md       # This file
```
