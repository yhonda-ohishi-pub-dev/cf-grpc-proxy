/**
 * Cloudflare Worker with Durable Object: gRPC-Web Proxy for CloudRun rust-logi
 *
 * Durable Objectを使用してIAMトークンをキャッシュし、
 * gRPC-WebリクエストをCloudRunにプロキシします。
 */

export interface Env {
  RUST_LOGI_URL: string;
  RUST_LOGI_PROXY_URL: string;
  GCP_SERVICE_ACCOUNT_JSON: string;
  GRPC_PROXY: DurableObjectNamespace;
}

interface ServiceAccountKey {
  client_email: string;
  private_key: string;
}

// CORSヘッダーを追加
function corsHeaders(origin: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Grpc-Web, X-User-Agent, Grpc-Timeout, Connect-Protocol-Version',
    'Access-Control-Expose-Headers': 'Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin',
    'Access-Control-Max-Age': '86400',
  };
}

/**
 * Durable Object: GrpcProxyDO
 * IAMトークンのキャッシュとgRPC-Webプロキシを管理
 */
export class GrpcProxyDO implements DurableObject {
  private state: DurableObjectState;
  private cachedToken: string | null = null;
  private tokenExpiry: number = 0;

  constructor(state: DurableObjectState, private env: Env) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const origin = request.headers.get('Origin');

    // CORS Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin),
      });
    }

    // gRPC-Webリクエストのみ処理
    if (request.method !== 'POST') {
      return new Response('Method not allowed', {
        status: 405,
        headers: corsHeaders(origin),
      });
    }

    try {
      const idToken = await this.getOrRefreshToken();

      // CloudRunへプロキシ（カスタムドメイン経由）
      const url = new URL(request.url);
      const targetUrl = `${this.env.RUST_LOGI_PROXY_URL}${url.pathname}`;

      const proxyHeaders = new Headers(request.headers);
      proxyHeaders.set('Authorization', `Bearer ${idToken}`);
      proxyHeaders.delete('Host');

      const bodyBuffer = await request.arrayBuffer();
      const proxyResponse = await fetch(targetUrl, {
        method: 'POST',
        headers: proxyHeaders,
        body: bodyBuffer,
      });

      // レスポンスにCORSヘッダーを追加
      const responseHeaders = new Headers(proxyResponse.headers);
      Object.entries(corsHeaders(origin)).forEach(([key, value]) => {
        responseHeaders.set(key, value);
      });

      return new Response(proxyResponse.body, {
        status: proxyResponse.status,
        headers: responseHeaders,
      });
    } catch (error) {
      console.error('Proxy error:', error);
      return new Response(
        JSON.stringify({ error: 'Internal server error', details: String(error) }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders(origin),
          },
        }
      );
    }
  }

  /**
   * IAMトークンを取得（キャッシュ有効なら再利用）
   */
  private async getOrRefreshToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    // キャッシュが有効ならそのまま返す（5分前に期限切れとみなす）
    if (this.cachedToken && this.tokenExpiry > now + 300) {
      return this.cachedToken;
    }

    // 新しいトークンを生成
    const token = await this.generateIdToken();
    this.cachedToken = token;
    this.tokenExpiry = now + 3600; // 1時間有効

    return token;
  }

  /**
   * Google Cloud用のIDトークンを生成
   * サービスアカウントのJWTを使ってGoogle OAuth2 APIからIDトークンを取得
   */
  private async generateIdToken(): Promise<string> {
    const serviceAccount: ServiceAccountKey = JSON.parse(this.env.GCP_SERVICE_ACCOUNT_JSON);

    const now = Math.floor(Date.now() / 1000);
    const exp = now + 3600;

    // JWT Header
    const header = {
      alg: 'RS256',
      typ: 'JWT',
    };

    // JWT Payload (Google OAuth2 token endpoint用)
    const payload = {
      iss: serviceAccount.client_email,
      sub: serviceAccount.client_email,
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: exp,
      target_audience: this.env.RUST_LOGI_URL,
    };

    const headerB64 = this.base64UrlEncode(JSON.stringify(header));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(payload));
    const unsignedToken = `${headerB64}.${payloadB64}`;

    // RSA署名
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      this.pemToArrayBuffer(serviceAccount.private_key),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      privateKey,
      new TextEncoder().encode(unsignedToken)
    );

    const signatureB64 = this.base64UrlEncode(
      String.fromCharCode(...new Uint8Array(signature))
    );

    const jwt = `${unsignedToken}.${signatureB64}`;

    // Google OAuth2 APIでIDトークンを取得
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,
      }),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      throw new Error(`Failed to get ID token: ${tokenResponse.status} ${errorText}`);
    }

    const tokenData = await tokenResponse.json() as { id_token: string };
    return tokenData.id_token;
  }

  private base64UrlEncode(data: string): string {
    return btoa(data)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  private pemToArrayBuffer(pem: string): ArrayBuffer {
    const base64 = pem
      .replace(/-----BEGIN PRIVATE KEY-----/g, '')
      .replace(/-----END PRIVATE KEY-----/g, '')
      .replace(/\s/g, '');

    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

/**
 * Worker エントリーポイント
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Durable Object IDを生成（シングルトン）
    const id = env.GRPC_PROXY.idFromName('grpc-proxy');
    const stub = env.GRPC_PROXY.get(id);

    // Durable Objectにリクエストを転送
    return stub.fetch(request);
  },
};
