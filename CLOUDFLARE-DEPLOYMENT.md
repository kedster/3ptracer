# 3ptracer - Cloudflare Deployment

This guide covers deploying 3ptracer to Cloudflare Pages with Workers for API proxying.

## Architecture

- **Cloudflare Pages**: Hosts the static frontend
- **Cloudflare Workers**: Provides API proxy for DNS queries and Certificate Transparency lookups
- **KV Storage**: Caches API responses for better performance

## Prerequisites

1. **Cloudflare Account**: Sign up at [cloudflare.com](https://cloudflare.com)
2. **Wrangler CLI**: Install the Cloudflare CLI tool
   ```bash
   npm install -g wrangler
   # or
   npm install wrangler --save-dev
   ```
3. **Authentication**: Login to Cloudflare
   ```bash
   wrangler login
   ```

## Configuration

### 1. Update Worker URL

Edit the `worker-url` meta tag in `index.html`:

```html
<meta name="worker-url" content="https://your-worker-name.your-subdomain.workers.dev">
```

### 2. Configure Wrangler

Update `wrangler.toml` with your details:

```toml
name = "3ptracer-worker"
account_id = "your-account-id"  # Add your account ID

[vars]
CORS_ORIGIN = "https://your-pages-domain.pages.dev"
```

### 3. Create KV Namespace

Create a KV namespace for caching:

```bash
wrangler kv:namespace create "CACHE"
wrangler kv:namespace create "CACHE" --preview
```

Update the KV namespace IDs in `wrangler.toml`.

## Deployment

### Quick Deploy

Use the provided deployment script:

```bash
./deploy-cloudflare.sh
```

### Manual Deploy

1. **Deploy Worker**:
   ```bash
   wrangler deploy
   ```

2. **Build and Deploy Pages**:
   ```bash
   npm run build
   wrangler pages deploy dist --project-name=3ptracer
   ```

## Features

### API Proxy (Worker)

The Cloudflare Worker provides these endpoints:

- `GET /api/health` - Health check
- `GET /api/dns?domain=example.com&type=A&provider=cloudflare` - DNS queries
- `GET /api/ct/crtsh?domain=example.com` - Certificate Transparency via crt.sh
- `GET /api/ct/certspotter?domain=example.com` - CertSpotter API
- `GET /api/ct/otx?domain=example.com` - OTX AlienVault API
- `GET /api/ct/hackertarget?domain=example.com` - HackerTarget API

### Frontend Features

- **Automatic Detection**: Detects Cloudflare Pages environment
- **Fallback Support**: Falls back to direct API calls if Worker is unavailable
- **Configuration Panel**: Shows deployment status and connectivity
- **Debug Mode**: Enhanced logging for troubleshooting

## Benefits

### Cloudflare Pages
- **Global CDN**: Fast loading worldwide
- **Automatic HTTPS**: SSL certificates managed automatically
- **Git Integration**: Automatic deployments from Git
- **Custom Domains**: Support for custom domains

### Cloudflare Workers
- **CORS Handling**: Eliminates cross-origin restrictions
- **Caching**: KV storage caches API responses
- **Rate Limiting**: Better control over API usage
- **Reliability**: Runs on Cloudflare's global network

## Environment Detection

The application automatically detects the deployment environment:

- **Cloudflare Pages**: Uses Worker API proxy
- **Other Environments**: Falls back to direct API calls

## Monitoring

### Configuration Panel

The frontend includes a configuration panel that shows:

- Current environment (Cloudflare Pages vs Direct)
- Worker health status
- API connectivity test results
- Debug mode toggle

### Health Checks

- Worker health: `GET /api/health`
- Connectivity test: Tests all DNS providers and CT sources
- Automatic fallback if Worker is unavailable

## Troubleshooting

### Common Issues

1. **Worker URL Not Updated**
   - Update the `worker-url` meta tag in index.html
   - Redeploy the Pages

2. **CORS Errors**
   - Check CORS_ORIGIN in wrangler.toml
   - Ensure Worker is deployed

3. **KV Namespace Issues**
   - Verify KV namespace IDs in wrangler.toml
   - Create namespaces if missing

4. **Authentication Errors**
   - Run `wrangler login` to authenticate
   - Check account ID in wrangler.toml

### Debug Mode

Enable debug mode in the configuration panel for detailed logging:

1. Open the configuration panel
2. Click "Debug Mode: OFF" to enable
3. Check browser console for detailed logs

## Performance

### Caching Strategy

The Worker implements caching for API responses:

- **DNS queries**: 5 minutes
- **Certificate Transparency**: 1 hour
- **Health checks**: No caching

### Global Distribution

Both Pages and Workers run on Cloudflare's global network, providing:

- Low latency worldwide
- High availability
- Automatic scaling

## Security

- **HTTPS Only**: All traffic encrypted
- **CORS Protection**: Configurable origin restrictions  
- **Rate Limiting**: Built into Cloudflare platform
- **No API Keys Exposed**: Worker proxies hide upstream API details

## Cost

- **Pages**: Free tier includes 500 builds/month, 20,000 requests/month
- **Workers**: Free tier includes 100,000 requests/day
- **KV**: Free tier includes 10 million reads/month, 1 million writes/month

For most use cases, 3ptracer will run entirely within the free tiers.

## Support

For deployment issues:
1. Check the Cloudflare Dashboard for error logs
2. Use debug mode for detailed client-side logging
3. Test connectivity with the configuration panel
4. Check Worker logs in the Cloudflare Dashboard