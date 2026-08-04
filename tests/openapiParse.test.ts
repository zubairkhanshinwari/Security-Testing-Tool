import { describe, it, expect } from 'vitest';
import { parseOpenApiDocument } from '../src/platform/engines/discovery/openapiParse';

describe('parseOpenApiDocument', () => {
  it('parses OpenAPI 3 paths and methods', () => {
    const doc = {
      openapi: '3.0.0',
      servers: [{ url: 'https://api.example.com' }],
      paths: {
        '/users': {
          get: { operationId: 'listUsers' },
          post: {
            operationId: 'createUser',
            parameters: [{ name: 'dryRun', in: 'query' }],
          },
        },
        '/users/{id}': {
          get: { parameters: [{ name: 'id', in: 'path' }] },
        },
      },
    };

    const eps = parseOpenApiDocument(doc, 'https://example.com', 80);
    expect(eps.length).toBeGreaterThanOrEqual(3);
    expect(eps.every((e) => e.source === 'openapi')).toBe(true);
    expect(eps.some((e) => e.method === 'GET' && /\/users$/.test(e.url))).toBe(true);
    expect(eps.some((e) => e.method === 'POST')).toBe(true);
    expect(eps.some((e) => e.url.includes('/users/1'))).toBe(true);
  });

  it('supports Swagger 2 host/basePath', () => {
    const doc = {
      swagger: '2.0',
      host: 'api.example.com',
      basePath: '/v1',
      schemes: ['https'],
      paths: {
        '/items': { get: {} },
      },
    };
    const eps = parseOpenApiDocument(doc, 'https://example.com');
    expect(eps).toHaveLength(1);
    expect(eps[0].url).toContain('api.example.com/v1/items');
    expect(eps[0].method).toBe('GET');
  });

  it('respects maxPaths', () => {
    const paths: Record<string, any> = {};
    for (let i = 0; i < 20; i++) paths[`/p${i}`] = { get: {} };
    const eps = parseOpenApiDocument({ openapi: '3.0.0', paths }, 'https://example.com', 5);
    expect(eps).toHaveLength(5);
  });

  it('returns empty for invalid docs', () => {
    expect(parseOpenApiDocument(null, 'https://example.com')).toEqual([]);
    expect(parseOpenApiDocument({}, 'https://example.com')).toEqual([]);
  });
});
