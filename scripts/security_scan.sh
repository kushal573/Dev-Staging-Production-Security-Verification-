name: Security Remediation Scan (ZAP + Custom Checks)

# ==========================================================================
# Covers Jira tickets:
#   - Enable SSL & Enforce HTTPS (Critical)
#   - Strengthen TLS & Transport Security
#   - Implement Security Headers
#   - Secure Cookies & Restrict Infrastructure Access
#   - Security Remediation - UpGuard Findings (Keepme.ai)
#
# Targets (hardcoded, no secrets/env vars):
#   dev        -> https://agentdev.keepme.ai/
#   staging    -> https://agentstaging.keepme.ai/
#   production -> https://agent.keepme.ai/
# ==========================================================================

on:
  push:
    branches: [ "**" ]
  workflow_dispatch: {}
  schedule:
    - cron: "0 3 * * *"   # daily 03:00 UTC, in addition to every push

permissions:
  contents: read
  pages: write
  id-token: write
  issues: write

jobs:
  # ------------------------------------------------------------------------
  # One job per environment. URLs are hardcoded per the requirement.
  # ------------------------------------------------------------------------
  scan:
    strategy:
      fail-fast: false
      matrix:
        include:
          - env_name: dev
            target_url: "https://agentdev.keepme.ai/"
            target_host: "agentdev.keepme.ai"
          - env_name: staging
            target_url: "https://agentstaging.keepme.ai/"
            target_host: "agentstaging.keepme.ai"
          - env_name: production
            target_url: "https://agent.keepme.ai/"
            target_host: "agent.keepme.ai"

    runs-on: ubuntu-latest
    continue-on-error: true   # let all 3 environments finish and report, even if one fails

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install scanning tools (curl, openssl, dig, nmap)
        run: |
          sudo apt-get update -y
          sudo apt-get install -y curl openssl dnsutils nmap

      - name: Make custom scan script executable
        run: chmod +x scripts/security_scan.sh

      # --------------------------------------------------------------
      # Custom checks: SSL cert validity/hostname match, TLS 1.0/1.1
      # disabled, TLS 1.2+/HSTS/preload, SPF/DMARC, SSH port exposure.
      # These are NOT covered by ZAP's passive scan.
      # --------------------------------------------------------------
      - name: Run custom TLS / SSL / SPF / DMARC / SSH checks
        id: custom_scan
        run: |
          ./scripts/security_scan.sh "${{ matrix.target_host }}" "custom_report_${{ matrix.env_name }}.html" "${{ matrix.env_name }}"
        continue-on-error: true

      # --------------------------------------------------------------
      # OWASP ZAP Baseline Scan: covers CSP, X-Frame-Options,
      # X-Content-Type-Options, X-Powered-By, HSTS presence,
      # cookie Secure/HttpOnly flags, and general passive-scan alerts.
      # --------------------------------------------------------------
      - name: OWASP ZAP Baseline Scan
        id: zap_scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: ${{ matrix.target_url }}
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a -j'
          artifact_name: "zap_report_${{ matrix.env_name }}"
          allow_issue_writing: false
        continue-on-error: true

      - name: Rename ZAP report for this environment
        if: always()
        run: |
          mkdir -p "reports/${{ matrix.env_name }}"
          [ -f custom_report_${{ matrix.env_name }}.html ] && cp custom_report_${{ matrix.env_name }}.html "reports/${{ matrix.env_name }}/custom_report.html" || echo "custom report missing"
          [ -f report_html.html ] && cp report_html.html "reports/${{ matrix.env_name }}/zap_report.html" || true
          [ -f report.html ] && cp report.html "reports/${{ matrix.env_name }}/zap_report.html" || true

      - name: Upload combined reports for this environment
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports-${{ matrix.env_name }}
          path: reports/${{ matrix.env_name }}/
          retention-days: 90

      - name: Fail job if custom checks or ZAP found high-severity issues
        if: always()
        run: |
          if [ "${{ steps.custom_scan.outcome }}" = "failure" ] || [ "${{ steps.zap_scan.outcome }}" = "failure" ]; then
            echo "::error::Security issues found in ${{ matrix.env_name }} (${{ matrix.target_url }}). See uploaded reports."
            exit 1
          fi

  # ------------------------------------------------------------------------
  # Publish all three environments' reports into a single GitHub Pages site
  # with a landing page linking dev / staging / production results.
  # ------------------------------------------------------------------------
  publish-report:
    needs: scan
    if: always()
    runs-on: ubuntu-latest
    steps:
      - name: Download all environment reports
        uses: actions/download-artifact@v4
        with:
          path: all-reports

      - name: Assemble Pages site
        run: |
          mkdir -p site/dev site/staging site/production
          cp -r all-reports/security-reports-dev/*        site/dev/        2>/dev/null || true
          cp -r all-reports/security-reports-staging/*    site/staging/    2>/dev/null || true
          cp -r all-reports/security-reports-production/* site/production/ 2>/dev/null || true

          cat > site/index.html <<'EOF'
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <title>Security Remediation - Keepme.ai</title>
            <style>
              body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#f6f8fa; margin:0; padding:2rem; }
              .container { max-width: 700px; margin: 0 auto; }
              h1 { font-size: 1.5rem; }
              .card { display:block; background:#fff; border:1px solid #d0d7de; border-radius:8px; padding:1.2rem 1.5rem; margin-bottom:1rem; text-decoration:none; color:#24292f; }
              .card:hover { border-color:#0969da; }
              .card h2 { margin:0 0 0.3rem; font-size:1.1rem; }
              .card p { margin:0; color:#57606a; font-size:0.85rem; }
              .env-dev { border-left:4px solid #9a6700; }
              .env-staging { border-left:4px solid #0969da; }
              .env-production { border-left:4px solid #cf222e; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Security Remediation Report - Keepme.ai</h1>
              <p style="color:#57606a;">Generated automatically on every push. Each environment has two reports: custom TLS/SSL/SPF/DMARC/SSH checks, and OWASP ZAP baseline scan.</p>

              <a class="card env-dev" href="dev/custom_report.html">
                <h2>Dev - Custom Checks</h2>
                <p>https://agentdev.keepme.ai/</p>
              </a>
              <a class="card env-dev" href="dev/zap_report.html">
                <h2>Dev - OWASP ZAP Report</h2>
                <p>https://agentdev.keepme.ai/</p>
              </a>

              <a class="card env-staging" href="staging/custom_report.html">
                <h2>Staging - Custom Checks</h2>
                <p>https://agentstaging.keepme.ai/</p>
              </a>
              <a class="card env-staging" href="staging/zap_report.html">
                <h2>Staging - OWASP ZAP Report</h2>
                <p>https://agentstaging.keepme.ai/</p>
              </a>

              <a class="card env-production" href="production/custom_report.html">
                <h2>Production - Custom Checks</h2>
                <p>https://agent.keepme.ai/</p>
              </a>
              <a class="card env-production" href="production/zap_report.html">
                <h2>Production - OWASP ZAP Report</h2>
                <p>https://agent.keepme.ai/</p>
              </a>
            </div>
          </body>
          </html>
          EOF

      - name: Upload Pages artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: site

      - name: Deploy to GitHub Pages
        uses: actions/deploy-pages@v4
