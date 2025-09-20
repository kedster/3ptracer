#!/bin/bash

# 3ptracer Cloudflare Deployment Script
# Builds and deploys both the Worker and Pages components

echo "🚀 Starting 3ptracer Cloudflare deployment..."

# Check if we're in the correct directory
if [ ! -f "index.html" ]; then
    echo "❌ Error: index.html not found. Please run this script from the project root directory."
    exit 1
fi

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    echo "❌ Error: Wrangler CLI not found. Please install it first:"
    echo "   npm install -g wrangler"
    echo "   # or"  
    echo "   npm install wrangler --save-dev"
    exit 1
fi

# Check if we're logged in to Cloudflare
echo "🔐 Checking Cloudflare authentication..."
if ! wrangler whoami &> /dev/null; then
    echo "❌ Error: Not logged in to Cloudflare. Please run 'wrangler login' first."
    exit 1
fi

echo "✅ Cloudflare authentication confirmed"

# Create dist directory for Pages deployment  
echo "📁 Creating dist directory..."
mkdir -p dist

# Copy files to dist
echo "📋 Copying files to dist directory..."

# Core HTML files
cp index.html dist/
cp about.html dist/

# CSS file
cp style.css dist/

# JavaScript files - Configuration and API
cp config.js dist/
cp api-client.js dist/

# JavaScript files - Core Application  
cp app.js dist/
cp dns-analyzer.js dist/
cp service-detection-engine.js dist/
cp data-processor.js dist/
cp ui-renderer.js dist/
cp analysis-controller.js dist/

# JavaScript files - Supporting modules
cp service-registry.js dist/
cp subdomain-registry.js dist/
cp export-manager.js dist/

# Add deployment timestamp
echo "📅 Generating build timestamp..."
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')
echo "// Build: $TIMESTAMP" >> dist/config.js

# Deploy the Worker first
echo "🔧 Deploying Cloudflare Worker..."
if wrangler deploy; then
    echo "✅ Worker deployed successfully"
else
    echo "❌ Worker deployment failed"
    exit 1
fi

# Deploy to Cloudflare Pages
echo "📦 Deploying to Cloudflare Pages..."
if wrangler pages deploy dist --project-name=3ptracer; then
    echo "✅ Pages deployed successfully"
else
    echo "❌ Pages deployment failed"
    exit 1
fi

# Show summary
echo ""
echo "🎉 Deployment completed successfully!"
echo "📅 Build timestamp: $TIMESTAMP"
echo "🔧 Worker: Deployed with API proxy and caching"
echo "📦 Pages: Deployed from dist/ directory"
echo ""
echo "📋 Deployed files:"
echo "   Frontend files:"
echo "      - index.html & about.html (main pages)"  
echo "      - style.css (styles)"
echo "      - config.js (configuration management)"
echo "      - api-client.js (API abstraction layer)"
echo "   Core application:"
echo "      - app.js (main application)"
echo "      - dns-analyzer.js (DNS analysis engine)"
echo "      - service-detection-engine.js (service detection)"
echo "      - data-processor.js (data processing)"
echo "      - ui-renderer.js (UI rendering)"  
echo "      - analysis-controller.js (analysis coordination)"
echo "   Supporting modules:"
echo "      - service-registry.js (service management)"
echo "      - subdomain-registry.js (subdomain management)"
echo "      - export-manager.js (export functionality)"
echo ""
echo "🌐 Your application should be available at:"
echo "   https://3ptracer.pages.dev"
echo ""
echo "🔧 Worker API endpoints:"
echo "   https://3ptracer-worker.your-subdomain.workers.dev/api/health"
echo "   https://3ptracer-worker.your-subdomain.workers.dev/api/dns"
echo "   https://3ptracer-worker.your-subdomain.workers.dev/api/ct/*"
echo ""
echo "💡 Note: Update the worker URL in config.js if needed"