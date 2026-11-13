import {
  handleAnalyzeMessageRequest,
  handleAnalyzeQrRequest,
  handleAnalyzeUrlRequest,
  handleAssistantChatRequest,
  handleExplainRetryRequest,
  handleHealthRequest,
  handleRescoreScansRequest,
} from '../../server/scannerHandlers.ts';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

export default async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const normalizedPath = url.pathname
    .replace(/^\/\.netlify\/functions\/api\/?/, '')
    .replace(/^\/api\/?/, '')
    .replace(/\/+$/, '');

  if (req.method === 'GET' && normalizedPath === 'health') {
    const result = await handleHealthRequest(
      url.searchParams.get('probe') || undefined,
      url.searchParams.get('model') || undefined
    );
    return jsonResponse(result.status, result.body);
  }

  if (req.method !== 'POST') {
    return jsonResponse(405, { error: 'Method not allowed' });
  }

  let body: unknown = {};
  try {
    body = await req.json();
  } catch {
    return jsonResponse(400, { error: 'Invalid JSON request body.' });
  }

  switch (normalizedPath) {
    case 'analyze/url': {
      const result = await handleAnalyzeUrlRequest(body);
      return jsonResponse(result.status, result.body);
    }
    case 'analyze/message': {
      const result = await handleAnalyzeMessageRequest(body);
      return jsonResponse(result.status, result.body);
    }
    case 'analyze/qr': {
      const result = await handleAnalyzeQrRequest(body);
      return jsonResponse(result.status, result.body);
    }
    case 'analyze/explain': {
      const result = await handleExplainRetryRequest(body);
      return jsonResponse(result.status, result.body);
    }
    case 'scans/rescore': {
      const result = await handleRescoreScansRequest(body);
      return jsonResponse(result.status, result.body);
    }
    case 'assistant/chat': {
      const result = await handleAssistantChatRequest(body);
      return jsonResponse(result.status, result.body);
    }
    default:
      return jsonResponse(404, { error: `Unknown API route: ${normalizedPath}` });
  }
}
