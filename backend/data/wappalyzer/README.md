"""Local Wappalyzer fingerprint catalog (optional).

Kickoff always runs the built-in Python engine in ``wappalyzer_service.py``.
Drop official open-source JSON here to expand coverage (themes, plugins, etc.):

  git clone --depth 1 https://github.com/tomnomnom/wappalyzer.git /tmp/wappalyzer
  mkdir -p technologies
  cp /tmp/wappalyzer/src/technologies/*.json technologies/

Or set ``WAPPALYZER_FINGERPRINTS_DIR`` to that folder.

Source: https://github.com/tomnomnom/wappalyzer  (GPL snapshot of the old engine)
"""
