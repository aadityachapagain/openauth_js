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
      let code, redirectUri, state;
      
      if (request.method === 'POST') {
        try {
          const body = await request.json();
          code = body.code;
          redirectUri = body.redirect_uri;
          state = body.state;
        } catch (e) {
          console.error('Failed to parse JSON body:', e);
          return new Response(JSON.stringify({ 
            error: 'Invalid JSON body',
            details: e.message
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      } else {
        code = url.searchParams.get('code');
        redirectUri = url.searchParams.get('redirect_uri');
        state = url.searchParams.get('state');
      }

      console.log('Processing callback:', { 
        method: request.method,
        code: code ? code.substring(0, 10) + '...' : 'missing',
        redirectUri,
        hasState: !!state
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

      // If state is present, verify it from KV storage to prevent CSRF
      if (state) {
        try {
          const stateKey = "state:" + state;
          const storedState = await env.OPENAUTH_KV.get(stateKey);
          if (!storedState) {
            console.error('Invalid state parameter:', state);
            return new Response(JSON.stringify({
              error: 'Invalid state parameter',
              details: 'State verification failed'
            }), {
              status: 400,
              headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
          }
          
          // State is valid, delete it from KV to prevent replay
          await env.OPENAUTH_KV.delete(stateKey);
        } catch (e) {
          console.error('State verification error:', e);
          // Continue even if state verification fails - this is just a warning
        }
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
        let errorDetail;
        try {
          errorDetail = await tokenResponse.text();
          // Try to parse as JSON for better error details
          try {
            errorDetail = JSON.parse(errorDetail);
          } catch (e) {
            // Keep as text if not valid JSON
          }
        } catch (e) {
          errorDetail = 'Could not read error response';
        }
        
        console.error('Token exchange failed:', {
          status: tokenResponse.status,
          error: errorDetail
        });
        
        return new Response(JSON.stringify({
          error: 'Token exchange failed',
          details: errorDetail,
          status: tokenResponse.status
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

      // If we got an id_token, store some user info in KV
      if (tokens.id_token && tokens.access_token) {
        try {
          // Get user info with the access token
          const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: {
              'Authorization': 'Bearer ' + tokens.access_token
            }
          });
          
          if (userInfoResponse.ok) {
            const userInfo = await userInfoResponse.json();
            // Store the user info in KV
            if (userInfo.sub) {
              const userKey = "user:" + userInfo.sub;
              await env.OPENAUTH_KV.put(
                userKey, 
                JSON.stringify({
                  email: userInfo.email,
                  name: userInfo.name,
                  picture: userInfo.picture,
                  lastLogin: new Date().toISOString()
                }),
                { expirationTtl: 86400 * 30 } // 30 days
              );
            }
          }
        } catch (e) {
          console.error('Failed to store user info:', e);
          // Non-fatal error, continue
        }
      }

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

        // Generate a random state parameter to prevent CSRF
        const state = crypto.randomUUID();
        
        // Store the state in KV with expiration
        try {
          const stateKey = "state:" + state;
          await env.OPENAUTH_KV.put(stateKey, new Date().toISOString(), {
            expirationTtl: 600 // 10 minutes
          });
        } catch (e) {
          console.error('Failed to store state:', e);
          // Continue even if state storage fails
        }

        const googleAuthUrl = 'https://accounts.google.com/o/oauth2/v2/auth' +
          '?client_id=' + encodeURIComponent(VARS.GOOGLE_CLIENT_ID) +
          '&redirect_uri=' + encodeURIComponent(redirectUri) +
          '&response_type=code' +
          '&scope=' + encodeURIComponent('email profile openid') +
          '&access_type=offline' +
          '&prompt=consent' + 
          '&state=' + encodeURIComponent(state);

        return Response.redirect(googleAuthUrl, 302);
      } else {
        return new Response(JSON.stringify({
          error: 'Unsupported provider',
          details: 'Provider \'' + provider + '\' is not supported'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
    }
    
    // Handle token refreshing
    if (url.pathname === '/refresh') {
      if (request.method !== 'POST') {
        return new Response(JSON.stringify({
          error: 'Method not allowed',
          details: 'Only POST method is allowed for token refresh'
        }), {
          status: 405,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      let refreshToken;
      try {
        const body = await request.json();
        refreshToken = body.refresh_token;
      } catch (e) {
        return new Response(JSON.stringify({
          error: 'Invalid request body',
          details: 'JSON parsing failed'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      if (!refreshToken) {
        return new Response(JSON.stringify({
          error: 'Missing refresh_token',
          details: 'refresh_token is required in the request body'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      const refreshResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: VARS.GOOGLE_CLIENT_ID,
          client_secret: VARS.GOOGLE_CLIENT_SECRET,
          refresh_token: refreshToken,
          grant_type: 'refresh_token',
        }),
      });
      
      if (!refreshResponse.ok) {
        let errorDetail;
        try {
          errorDetail = await refreshResponse.text();
        } catch (e) {
          errorDetail = 'Could not read error response';
        }
        
        return new Response(JSON.stringify({
          error: 'Token refresh failed',
          details: errorDetail
        }), {
          status: refreshResponse.status,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }
      
      const newTokens = await refreshResponse.json();
      return new Response(JSON.stringify(newTokens), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
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
  ENVIRONMENT: "${var.environment}",
  AUTH_SECRET: "${var.auth_secret}"
};
EOT

  kv_namespace_binding {
    name         = "OPENAUTH_KV"
    namespace_id = cloudflare_workers_kv_namespace.openauth_storage.id
  }
}


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
        url.pathname === '/refresh' ||
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
      "connect-src 'self' https://accounts.google.com https://www.googleapis.com http://localhost:3000"
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