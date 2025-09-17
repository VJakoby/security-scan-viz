#!/bin/sh

echo "=========================================="
echo "🚀 Vulnerability Dashboard Starting..."
echo "=========================================="
echo ""
echo "📍 Application will be available at:"
echo "   🌐 http://localhost:8888"
echo ""
echo "🐳 Container: vulnerability-dashboard"
echo "🔧 Server: nginx"
echo "📂 Static files: /usr/share/nginx/html"
echo ""
echo "=========================================="
echo "✅ Starting nginx server on port 8888..."
echo "=========================================="

# Start nginx
exec nginx -g "daemon off;"