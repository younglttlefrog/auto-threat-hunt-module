import { IRouter } from '../../../../core/server';
import http from 'http';

function getJsonFromLocalApi(path: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { hostname: '127.0.0.1', port: 8089, path, timeout: 30000 },
      (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error(data || String(e))); }
        });
      }
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout connecting to hunt API'));
    });
  });
}

function normalizePayload(raw: any): any {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw);
    } catch (e) {
      return {};
    }
  }
  if (raw.body && typeof raw.body === 'string') {
    try {
      return JSON.parse(raw.body);
    } catch (e) {
      return raw;
    }
  }
  return raw;
}

function postJsonToLocalApi(path: string, payload: any = {}): Promise<any> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(normalizePayload(payload));

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: 8089,
        path,
        method: 'POST',
        timeout: 300000,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';

        res.on('data', (chunk) => data += chunk);

        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error(data || String(e))); }
        });
      }
    );

    req.on('error', reject);

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout connecting to hunt API'));
    });

    req.write(body);
    req.end();
  });
}

function getBinaryFromLocalApi(path: string): Promise<{ data: Buffer; contentType: string }> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { hostname: '127.0.0.1', port: 8089, path, timeout: 30000 },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          resolve({
            data: Buffer.concat(chunks),
            contentType: String(res.headers['content-type'] || 'application/octet-stream'),
          });
        });
      }
    );

    req.on('error', reject);

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout downloading report'));
    });
  });
}

function getFilename(request: any): string {
  const fromQuery = request.query?.filename;
  const fromUrl = request.url?.searchParams?.get('filename');
  return String(fromQuery || fromUrl || '');
}

export function defineRoutes(router: IRouter) {
  router.get(
    { path: '/api/auto_threat_hunt/latest', validate: false },
    async (context, request, response) => {
      try {
        const body = await getJsonFromLocalApi('/api/hunt/latest');
        return response.ok({ body });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message || String(e) } });
      }
    }
  );

  router.post(
    { path: '/api/auto_threat_hunt/run', validate: false },
    async (context, request, response) => {
      try {
        const payload = normalizePayload(request.body || {});
        const body = await postJsonToLocalApi('/api/hunt/run', payload);
        return response.ok({ body });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message || String(e) } });
      }
    }
  );

  router.post(
    { path: '/api/auto_threat_hunt/report/executive', validate: false },
    async (context, request, response) => {
      try {
        const payload = normalizePayload(request.body || {});
        const body = await postJsonToLocalApi('/api/hunt/report/executive', payload);
        return response.ok({ body });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message || String(e) } });
      }
    }
  );

  router.get(
    { path: '/api/auto_threat_hunt/reports', validate: false },
    async (context, request, response) => {
      try {
        const body = await getJsonFromLocalApi('/api/hunt/reports');
        return response.ok({ body });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message || String(e) } });
      }
    }
  );

  router.get(
    { path: '/api/auto_threat_hunt/report', validate: false },
    async (context, request, response) => {
      try {
        const filename = getFilename(request);
        if (!filename) {
          return response.customError({ statusCode: 400, body: { message: 'Missing filename in plugin route' } });
        }

        const body = await getJsonFromLocalApi(`/api/hunt/report?filename=${encodeURIComponent(filename)}`);
        return response.ok({ body });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message || String(e) } });
      }
    }
  );

  router.get(
    { path: '/api/auto_threat_hunt/report/download', validate: false },
    async (context, request, response) => {
      try {
        const filename = getFilename(request);
        if (!filename) {
          return response.customError({ statusCode: 400, body: { message: 'Missing filename in download route' } });
        }

        const result = await getBinaryFromLocalApi(`/api/hunt/report/download?filename=${encodeURIComponent(filename)}`);

        return response.ok({
          body: result.data,
          headers: {
            'content-type': result.contentType,
            'content-disposition': `attachment; filename="${filename}"`,
          },
        });
      } catch (e: any) {
        return response.customError({ statusCode: 500, body: { message: e.message || String(e) } });
      }
    }
  );
}
