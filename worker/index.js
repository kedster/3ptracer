/**
 * Cloudflare Worker for 3ptracer API Proxy
 * Handles DNS queries, Certificate Transparency lookups, and other API calls
 * Provides CORS support and caching for better performance
 */

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 200,
        headers: corsHeaders,
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Route API requests
      if (path.startsWith('/api/dns')) {
        return await handleDNSQuery(request, env);
      } else if (path.startsWith('/api/ct/crtsh')) {
        return await handleCrtShQuery(request, env);
      } else if (path.startsWith('/api/ct/certspotter')) {
        return await handleCertSpotterQuery(request, env);
      } else if (path.startsWith('/api/ct/otx')) {
        return await handleOTXQuery(request, env);
      } else if (path.startsWith('/api/ct/hackertarget')) {
        return await handleHackerTargetQuery(request, env);
      } else if (path === '/api/health') {
        return new Response(JSON.stringify({
          status: 'ok',
          timestamp: new Date().toISOString(),
          service: '3ptracer-worker'
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Default response for unknown routes
      return new Response('Not Found', {
        status: 404,
        headers: corsHeaders,
      });
    } catch (error) {
      console.error('Worker error:', error);
      return new Response(JSON.stringify({
        error: 'Internal Server Error',
        message: error.message
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
  },
};

/**
 * Handle DNS over HTTPS queries
 */
async function handleDNSQuery(request, env) {
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');
  const type = url.searchParams.get('type') || 'A';
  const provider = url.searchParams.get('provider') || 'cloudflare';

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Domain parameter required' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // Check cache first
  const cacheKey = `dns:${provider}:${domain}:${type}`;
  const cached = await env.CACHE?.get(cacheKey);
  if (cached) {
    return new Response(cached, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    let dohUrl;
    switch (provider) {
      case 'cloudflare':
        dohUrl = `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`;
        break;
      case 'google':
        dohUrl = `https://dns.google/resolve?name=${domain}&type=${type}`;
        break;
      case 'quad9':
        dohUrl = `https://dns.quad9.net:5053/dns-query?name=${domain}&type=${type}`;
        break;
      default:
        dohUrl = `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`;
    }

    const response = await fetch(dohUrl, {
      headers: {
        'Accept': 'application/dns-json',
        'User-Agent': '3ptracer-worker/1.0'
      },
    });

    if (!response.ok) {
      throw new Error(`DNS query failed: ${response.status}`);
    }

    const data = await response.text();
    
    // Cache for 5 minutes
    await env.CACHE?.put(cacheKey, data, { expirationTtl: 300 });

    return new Response(data, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'DNS query failed',
      message: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Handle Certificate Transparency crt.sh queries
 */
async function handleCrtShQuery(request, env) {
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Domain parameter required' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const cacheKey = `crtsh:${domain}`;
  const cached = await env.CACHE?.get(cacheKey);
  if (cached) {
    return new Response(cached, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const response = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': '3ptracer-worker/1.0'
      },
    });

    if (!response.ok) {
      throw new Error(`crt.sh query failed: ${response.status}`);
    }

    const data = await response.text();
    
    // Cache for 1 hour
    await env.CACHE?.put(cacheKey, data, { expirationTtl: 3600 });

    return new Response(data, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'crt.sh query failed',
      message: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Handle CertSpotter queries
 */
async function handleCertSpotterQuery(request, env) {
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Domain parameter required' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const cacheKey = `certspotter:${domain}`;
  const cached = await env.CACHE?.get(cacheKey);
  if (cached) {
    return new Response(cached, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const response = await fetch(`https://certspotter.com/api/v0/certs?domain=${domain}`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': '3ptracer-worker/1.0'
      },
    });

    if (!response.ok) {
      throw new Error(`CertSpotter query failed: ${response.status}`);
    }

    const data = await response.text();
    
    // Cache for 1 hour
    await env.CACHE?.put(cacheKey, data, { expirationTtl: 3600 });

    return new Response(data, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'CertSpotter query failed',
      message: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Handle OTX AlienVault queries
 */
async function handleOTXQuery(request, env) {
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Domain parameter required' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const cacheKey = `otx:${domain}`;
  const cached = await env.CACHE?.get(cacheKey);
  if (cached) {
    return new Response(cached, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': '3ptracer-worker/1.0'
      },
    });

    if (!response.ok) {
      throw new Error(`OTX query failed: ${response.status}`);
    }

    const data = await response.text();
    
    // Cache for 1 hour
    await env.CACHE?.put(cacheKey, data, { expirationTtl: 3600 });

    return new Response(data, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'OTX query failed',
      message: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}

/**
 * Handle HackerTarget queries
 */
async function handleHackerTargetQuery(request, env) {
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Domain parameter required' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const cacheKey = `hackertarget:${domain}`;
  const cached = await env.CACHE?.get(cacheKey);
  if (cached) {
    return new Response(cached, {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const response = await fetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`, {
      headers: {
        'User-Agent': '3ptracer-worker/1.0'
      },
    });

    if (!response.ok) {
      throw new Error(`HackerTarget query failed: ${response.status}`);
    }

    const data = await response.text();
    
    // Cache for 1 hour
    await env.CACHE?.put(cacheKey, data, { expirationTtl: 3600 });

    return new Response(data, {
      headers: { ...corsHeaders, 'Content-Type': 'text/plain' },
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'HackerTarget query failed',
      message: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}