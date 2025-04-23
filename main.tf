terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

locals {
  worker_name = "openauth-${var.environment}"
}

# Create KV namespace
resource "cloudflare_workers_kv_namespace" "openauth_storage" {
  account_id = var.cloudflare_account_id
  title      = "openauth-storage-${var.environment}"
}

resource "cloudflare_workers_script" "openauth" {
  account_id = var.cloudflare_account_id
  name       = local.worker_name

  content    = <<EOT
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event.env).catch(err => {
    console.error('Worker error:', {
      message: err.message,
      stack: err.stack,
      url: event.request.url
    });
    return new Response(JSON.stringify({
      error: 'Worker error',
      message: err.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }));
});

async function handleRequest(request, env) {
  const url = new URL(request.url);
  console.log('Request:', {
    url: url.toString(),
    path: url.pathname,
    method: request.method
  });
  
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Handle OAuth callback
    if (url.pathname === '/callback') {
      let code, redirectUri;
      
      if (request.method === 'POST') {
        const body = await request.json();
        code = body.code;
        redirectUri = body.redirect_uri;
      } else {
        code = url.searchParams.get('code');
        redirectUri = url.searchParams.get('redirect_uri');
      }

      console.log('Processing callback:', { 
        method: request.method,
        code: code ? code.substring(0, 10) + '...' : 'missing',
        redirectUri
      });

      if (!code) {
        return new Response(JSON.stringify({ 
          error: 'Missing code parameter',
          details: { method: request.method }
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      console.log('Exchanging code for tokens');

      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          code,
          client_id: VARS.GOOGLE_CLIENT_ID,
          client_secret: VARS.GOOGLE_CLIENT_SECRET,
          redirect_uri: redirectUri || 'http://localhost:3000/api/callback',
          grant_type: 'authorization_code',
        }),
      });

      if (!tokenResponse.ok) {
        const error = await tokenResponse.text();
        console.error('Token exchange failed:', {
          status: tokenResponse.status,
          error: error
        });
        return new Response(JSON.stringify({
          error: 'Token exchange failed',
          details: error
        }), {
          status: tokenResponse.status,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const tokens = await tokenResponse.json();
      console.log('Received tokens:', {
        access_token: tokens.access_token ? '✓' : '✗',
        refresh_token: tokens.refresh_token ? '✓' : '✗',
        id_token: tokens.id_token ? '✓' : '✗'
      });

      return new Response(JSON.stringify(tokens), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // Handle OAuth authorization
    if (url.pathname === '/authorize') {
      const provider = url.searchParams.get('provider');
      const clientId = url.searchParams.get('client_id');
      const redirectUri = url.searchParams.get('redirect_uri');
      
      console.log('Auth request:', { provider, clientId, redirectUri });

      if (provider === 'google') {
        if (!VARS.GOOGLE_CLIENT_ID) {
          console.error('Missing Google configuration:', { 
            hasClientId: !!VARS.GOOGLE_CLIENT_ID,
            hasClientSecret: !!VARS.GOOGLE_CLIENT_SECRET
          });
          
          return new Response(JSON.stringify({
            error: 'OAuth configuration error',
            details: 'Google credentials not configured'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }

        const googleAuthUrl = 'https://accounts.google.com/o/oauth2/v2/auth' +
          '?client_id=' + encodeURIComponent(VARS.GOOGLE_CLIENT_ID) +
          '&redirect_uri=' + encodeURIComponent(redirectUri) +
          '&response_type=code' +
          '&scope=' + encodeURIComponent('email profile openid') +
          '&access_type=offline' +
          '&prompt=consent';

        return Response.redirect(googleAuthUrl, 302);
      }
    }
    
    return new Response(JSON.stringify({ 
      error: 'Not found',
      path: url.pathname 
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (error) {
    console.error('Request failed:', error);
    return new Response(JSON.stringify({ 
      error: error.message,
      details: error.stack
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

const VARS = {
  GOOGLE_CLIENT_ID: "${var.google_client_id}",
  GOOGLE_CLIENT_SECRET: "${var.google_client_secret}",
  ENVIRONMENT: "${var.environment}"
};
EOT

  kv_namespace_binding {
    name         = "OPENAUTH_KV"
    namespace_id = cloudflare_workers_kv_namespace.openauth_storage.id
  }
}

# Security headers worker
resource "cloudflare_workers_script" "security_headers" {
  account_id = var.cloudflare_account_id
  name       = "${local.worker_name}-security"
  content    = <<EOT
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request).catch(err => {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }));
})

async function handleRequest(request) {
  try {
    const url = new URL(request.url);

    // Skip security for auth-related paths
    if (url.pathname === '/authorize' || 
        url.pathname === '/callback' || 
        url.pathname.startsWith('/api/')) {
      return fetch(request);
    }

    const response = await fetch(request);
    const newHeaders = new Headers(response.headers);

    // Security headers
    newHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    newHeaders.set('X-Content-Type-Options', 'nosniff');
    newHeaders.set('X-Frame-Options', 'DENY');
    newHeaders.set('X-XSS-Protection', '1; mode=block');
    newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Relaxed CSP for auth flows
    newHeaders.set('Content-Security-Policy', 
      "default-src 'self' https://accounts.google.com; " +
      "script-src 'self' 'unsafe-inline' https://accounts.google.com; " +
      "style-src 'self' 'unsafe-inline' https://accounts.google.com; " +
      "frame-src https://accounts.google.com; " +
      "connect-src 'self' https://accounts.google.com http://localhost:3000"
    );

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
EOT
}