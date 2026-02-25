/**
 * Cloudflare Worker with Durable Object: gRPC-Web Proxy for CloudRun rust-logi
 *
 * Durable Objectを使用してIAMトークンをキャッシュし、
 * gRPC-WebリクエストをCloudRunにプロキシします。
 * JWT検証ゲートにより、認証済みリクエストのみをCloudRunに転送します。
 * 
 *
 * ItemsSyncDO: WebSocket Hibernation APIを使ったマルチブラウザ同期
 */

import { DurableObject as BaseDurableObject } from 'cloudflare:workers';

export interface Env {
  RUST_LOGI_URL: string;
  RUST_LOGI_PROXY_URL: string;
  GCP_SERVICE_ACCOUNT_JSON: string;
  GRPC_PROXY: DurableObjectNamespace;
  ITEMS_SYNC: DurableObjectNamespace;
  JWT_SECRET: string;
}

interface ServiceAccountKey {
  client_email: string;
  private_key: string;
}

/** JWT Claims structure (matches rust-logi src/services/auth_service.rs Claims) */
interface JwtPayload {
  sub: string;      // user_id
  org: string;      // organization_id
  username: string;
  exp: number;
  iat: number;
}

/** Public paths that do not require JWT authentication (synced with rust-logi src/middleware/auth.rs) */
const PUBLIC_PATHS: string[] = [
  '/logi.auth.AuthService/Login',
  '/logi.auth.AuthService/SignUpWithGoogle',
  '/logi.auth.AuthService/LoginWithGoogle',
  '/logi.auth.AuthService/ValidateToken',
  '/logi.auth.AuthService/ResolveSsoProvider',
  '/logi.auth.AuthService/LoginWithSsoProvider',
  '/logi.member.MemberService/AcceptInvitation',
  '/grpc.health.v1.Health/Check',
  '/grpc.health.v1.Health/Watch',
  '/grpc.reflection.v1.ServerReflection/ServerReflectionInfo',
  '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
];

/**
 * gRPC-Web trailer-only エラーレスポンスを生成
 * connect-web が正しくパースできる形式（JSON ではなく gRPC-Web フレーム）
 */
function grpcWebError(
  grpcStatus: number,
  message: string,
  origin: string | null,
): Response {
  const trailerText = `grpc-status: ${grpcStatus}\r\ngrpc-message: ${encodeURIComponent(message)}\r\n`;
  const trailerBytes = new TextEncoder().encode(trailerText);
  const frame = new Uint8Array(5 + trailerBytes.length);
  frame[0] = 0x80; // trailer frame flag
  new DataView(frame.buffer).setUint32(1, trailerBytes.length);
  frame.set(trailerBytes, 5);

  return new Response(frame, {
    status: 200, // gRPC-Web always returns HTTP 200
    headers: {
      'Content-Type': 'application/grpc-web+proto',
      'Content-Length': String(frame.length),
      ...corsHeaders(origin),
    },
  });
}

// CORSヘッダーを追加
function corsHeaders(origin: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Grpc-Web, X-User-Agent, Grpc-Timeout, Connect-Protocol-Version, Authorization, X-Organization-Id, X-Auth-Token',
    'Access-Control-Expose-Headers': 'Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin',
    'Access-Control-Max-Age': '86400',
  };
}

/** Base64URL decode to ArrayBuffer */
function base64UrlDecodeToBuffer(str: string): ArrayBuffer {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/** Verify HS256 JWT using Web Crypto API */
async function verifyJwt(token: string, secret: string): Promise<JwtPayload | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;

    // Import key for HMAC-SHA256
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );

    // Verify signature
    const signatureBytes = base64UrlDecodeToBuffer(signatureB64!);
    const dataBytes = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

    const valid = await crypto.subtle.verify('HMAC', key, signatureBytes, dataBytes);
    if (!valid) return null;

    // Decode payload
    const payloadJson = atob(payloadB64!.replace(/-/g, '+').replace(/_/g, '/'));
    const payload: JwtPayload = JSON.parse(payloadJson);

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;

    return payload;
  } catch {
    return null;
  }
}

/**
 * Durable Object: GrpcProxyDO
 * IAMトークンのキャッシュ、JWT検証ゲート、gRPC-Webプロキシを管理
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
      // --- JWT検証ゲート ---
      const url = new URL(request.url);
      const path = url.pathname;
      let jwtPayload: JwtPayload | null = null;

      if (!PUBLIC_PATHS.includes(path)) {
        const authToken = request.headers.get('x-auth-token');

        if (authToken) {
          jwtPayload = await verifyJwt(authToken, this.env.JWT_SECRET);
          if (!jwtPayload) {
            return grpcWebError(16, 'Invalid or expired token', origin); // UNAUTHENTICATED
          }
        } else {
          // 移行期間: JWTなしでも警告のみで通過（厳格モード時はここで401を返す）
          console.warn(`[AUTH] Unauthenticated request to ${path} - allowing during transition`);
        }
      }

      // --- バックエンドへプロキシ ---
      const targetUrl = `${this.env.RUST_LOGI_PROXY_URL}${url.pathname}`;

      const proxyHeaders = new Headers(request.headers);
      // Cloud Run使用時のみIAMトークンを付与（CF Containers時はGCP_SERVICE_ACCOUNT_JSONが未設定）
      if (this.env.GCP_SERVICE_ACCOUNT_JSON) {
        const idToken = await this.getOrRefreshToken();
        proxyHeaders.set('Authorization', `Bearer ${idToken}`);
      }
      proxyHeaders.delete('Host');
      // x-auth-token はrust-logiのauth middlewareでJWT検証するため転送する

      // JWT検証成功時: ユーザー情報ヘッダーを注入
      if (jwtPayload) {
        proxyHeaders.set('x-user-id', jwtPayload.sub);
        // クライアント指定のx-organization-idを保持（rust-logi middleware側でメンバーシップ検証）
        const existingOrgId = proxyHeaders.get('x-organization-id');
        if (!existingOrgId || existingOrgId.trim() === '') {
          proxyHeaders.set('x-organization-id', jwtPayload.org);
        }
      }

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
      return grpcWebError(13, `Internal server error: ${String(error)}`, origin); // INTERNAL
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
 * Durable Object: ItemsSyncDO (WebSocket Hibernation API)
 * マルチブラウザ同期: アイテムCRUD通知をWebSocketでブロードキャスト
 * Room粒度: org_id単位 (items-{orgId})
 */
export class ItemsSyncDO extends BaseDurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // ping/pong をDO起動なしで自動応答（Hibernation中もコネクション維持）
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair('ping', 'pong'),
    );
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected WebSocket', { status: 426 });
    }

    // JWTをクエリパラメータから検証（WebSocketはカスタムヘッダー不可）
    const url = new URL(request.url);
    const token = url.searchParams.get('token');
    if (!token) {
      return new Response('Missing token', { status: 401 });
    }

    const payload = await verifyJwt(token, this.env.JWT_SECRET);
    if (!payload) {
      return new Response('Invalid or expired token', { status: 401 });
    }

    // WebSocketペア作成
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // Hibernation API: acceptWebSocket + userIdタグ（personalアイテムフィルタ用）
    this.ctx.acceptWebSocket(server, [payload.sub]);
    server.serializeAttachment({ userId: payload.sub });

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string') return;

    try {
      const data = JSON.parse(message);
      if (data.type !== 'items_changed') return;

      const sender = ws.deserializeAttachment() as { userId: string };

      const broadcastMsg = JSON.stringify({
        type: 'items_changed',
        action: data.action,
        parentId: data.parentId,
        ownerType: data.ownerType,
        userId: sender.userId,
      });

      // 全接続クライアントに配信（送信元除外）
      for (const sock of this.ctx.getWebSockets()) {
        if (sock === ws) continue;

        if (data.ownerType === 'personal') {
          // personalアイテム: 同一ユーザーの別デバイスにのみ通知
          const att = sock.deserializeAttachment() as { userId: string } | null;
          if (att?.userId === sender.userId) {
            sock.send(broadcastMsg);
          }
        } else {
          // orgアイテム: 全員に通知
          sock.send(broadcastMsg);
        }
      }
    } catch {
      // malformed message は無視
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    ws.close(code, reason);
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    console.error('ItemsSyncDO WebSocket error:', error);
    ws.close(1011, 'Internal error');
  }
}

/**
 * Worker エントリーポイント
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // WebSocket同期: /ws/items/{orgId}
    if (url.pathname.startsWith('/ws/items/')) {
      const orgId = url.pathname.split('/')[3];
      if (!orgId) {
        return new Response('Missing orgId', { status: 400 });
      }

      // CORS preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: corsHeaders(request.headers.get('Origin')),
        });
      }

      // org_id単位でDOインスタンスを分離
      const doId = env.ITEMS_SYNC.idFromName(`items-${orgId}`);
      return env.ITEMS_SYNC.get(doId).fetch(request);
    }

    // gRPCプロキシ（シングルトン）
    const id = env.GRPC_PROXY.idFromName('grpc-proxy');
    const stub = env.GRPC_PROXY.get(id);
    return stub.fetch(request);
  },
};
