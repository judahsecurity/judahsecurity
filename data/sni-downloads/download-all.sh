#!/bin/bash
# Download SNI IP Ranges files locally
# These are large files (100-500MB each), total ~1-2GB

cd "$(dirname "$0")"

echo "=== SNI IP Ranges Downloader ==="
echo "Downloading to: $(pwd)"
echo ""

# Download each provider's file
providers=("amazon" "digitalocean" "google" "microsoft" "oracle")

for provider in "${providers[@]}"; do
    url="https://kaeferjaeger.gay/sni-ip-ranges/${provider}/ipv4_merged_sni.txt"
    output="${provider}_ipv4_merged_sni.txt"
    
    echo "----------------------------------------"
    echo "Downloading: ${provider}"
    echo "URL: ${url}"
    echo "Output: ${output}"
    echo ""
    
    # Use curl with progress bar, resume support, and retry
    curl -L -C - --retry 3 --retry-delay 5 -o "${output}" "${url}"
    
    if [ $? -eq 0 ]; then
        size=$(ls -lh "${output}" | awk '{print $5}')
        echo "✓ ${provider} complete: ${size}"
    else
        echo "✗ ${provider} FAILED"
    fi
    echo ""
done

echo "=== Download Complete ==="
echo ""
ls -lh *.txt 2>/dev/null || echo "No files downloaded"
echo ""
echo "Total size:"
du -sh . 2>/dev/null

echo ""
echo "Next step: Upload to S3 with:"
echo "  aws s3 cp . s3://judahsecurity-asm-cloud/sni-raw/ --recursive --exclude '*' --include '*.txt'"
