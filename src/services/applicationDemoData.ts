import { LogEvent } from '../types';

/**
 * Realistic Simulated Application / Web / API Events
 * Clearly marked as DEMO DATA for Application Security Agent.
 */
export const DEMO_APPLICATION_LOGS: LogEvent[] = [
  // 1. SQL Injection / Scanner Reconnaissance
  {
    id: 'APP-DEMO-001',
    timestamp: '2026-09-11 22:51:30',
    source: 'Nginx Ingress / ModSecurity WAF',
    logType: 'APPLICATION',
    message: 'GET /api/v2/items?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1 403',
    rawData: '192.168.1.105 - - [11/Sep/2026:22:51:30 +0000] "GET /api/v2/items?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 403 521 "-" "sqlmap/1.7.1#stable"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Billing & Catalog Service v2',
      httpMethod: 'GET',
      endpoint: '/api/v2/items?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--',
      statusCode: 403,
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      userAgent: 'sqlmap/1.7.1#stable',
      payloadSnippet: "id=1' UNION SELECT null,username,password FROM users--"
    }
  },
  {
    id: 'APP-DEMO-002',
    timestamp: '2026-09-11 22:51:31',
    source: 'Nginx Ingress / ModSecurity WAF',
    logType: 'APPLICATION',
    message: 'GET /api/v2/items?id=1%27%20AND%201=1-- HTTP/1.1 200',
    rawData: '192.168.1.105 - - [11/Sep/2026:22:51:31 +0000] "GET /api/v2/items?id=1%27%20AND%201=1-- HTTP/1.1" 200 892 "-" "sqlmap/1.7.1#stable"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Billing & Catalog Service v2',
      httpMethod: 'GET',
      endpoint: '/api/v2/items?id=1%27%20AND%201=1--',
      statusCode: 200,
      sourceIp: '192.168.1.105',
      destinationIp: '10.0.0.5',
      userAgent: 'sqlmap/1.7.1#stable',
      payloadSnippet: "id=1' AND 1=1--"
    }
  },

  // 2. Directory / Path Traversal Attack
  {
    id: 'APP-DEMO-003',
    timestamp: '2026-09-11 22:53:10',
    source: 'API Gateway Envoy Proxy',
    logType: 'APPLICATION',
    message: 'GET /static/../../../../etc/passwd HTTP/1.1 404',
    rawData: '192.168.1.105 - - [11/Sep/2026:22:53:10 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 404 230 "-" "curl/7.88.1"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Document & Static Asset Service',
      httpMethod: 'GET',
      endpoint: '/static/../../../../etc/passwd',
      statusCode: 404,
      sourceIp: '192.168.1.105',
      userAgent: 'curl/7.88.1',
      payloadSnippet: 'QueryParam path=../../../../etc/passwd'
    }
  },
  {
    id: 'APP-DEMO-004',
    timestamp: '2026-09-11 22:53:15',
    source: 'API Gateway Envoy Proxy',
    logType: 'APPLICATION',
    message: 'GET /static/%2e%2e%2f%2e%2e%2fwin.ini HTTP/1.1 404',
    rawData: '192.168.1.105 - - [11/Sep/2026:22:53:15 +0000] "GET /static/%2e%2e%2f%2e%2e%2fwin.ini HTTP/1.1" 404 230 "-" "curl/7.88.1"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Document & Static Asset Service',
      httpMethod: 'GET',
      endpoint: '/static/%2e%2e%2f%2e%2e%2fwin.ini',
      statusCode: 404,
      sourceIp: '192.168.1.105',
      userAgent: 'curl/7.88.1',
      payloadSnippet: 'Encoded traversal: %2e%2e%2f%2e%2e%2fwin.ini'
    }
  },

  // 3. Repeated Authentication Failures & Subsequent Login Success (admin account)
  {
    id: 'APP-DEMO-005',
    timestamp: '2026-09-11 22:52:01',
    source: 'Keycloak Auth Gateway',
    logType: 'APPLICATION',
    message: 'POST /api/v1/auth/login HTTP/1.1 401 Unauthorized',
    rawData: '10.240.12.88 - admin [11/Sep/2026:22:52:01 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 128 "https://corp.internal/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Identity & SSO Gateway',
      httpMethod: 'POST',
      endpoint: '/api/v1/auth/login',
      statusCode: 401,
      sourceIp: '10.240.12.88',
      userName: 'admin',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      payloadSnippet: 'username=admin&auth_type=password'
    }
  },
  {
    id: 'APP-DEMO-006',
    timestamp: '2026-09-11 22:52:03',
    source: 'Keycloak Auth Gateway',
    logType: 'APPLICATION',
    message: 'POST /api/v1/auth/login HTTP/1.1 401 Unauthorized',
    rawData: '10.240.12.88 - admin [11/Sep/2026:22:52:03 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 128 "https://corp.internal/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Identity & SSO Gateway',
      httpMethod: 'POST',
      endpoint: '/api/v1/auth/login',
      statusCode: 401,
      sourceIp: '10.240.12.88',
      userName: 'admin',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      payloadSnippet: 'username=admin&auth_type=password'
    }
  },
  {
    id: 'APP-DEMO-007',
    timestamp: '2026-09-11 22:52:05',
    source: 'Keycloak Auth Gateway',
    logType: 'APPLICATION',
    message: 'POST /api/v1/auth/login HTTP/1.1 401 Unauthorized',
    rawData: '10.240.12.88 - admin [11/Sep/2026:22:52:05 +0000] "POST /api/v1/auth/login HTTP/1.1" 401 128 "https://corp.internal/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Identity & SSO Gateway',
      httpMethod: 'POST',
      endpoint: '/api/v1/auth/login',
      statusCode: 401,
      sourceIp: '10.240.12.88',
      userName: 'admin',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      payloadSnippet: 'username=admin&auth_type=password'
    }
  },
  {
    id: 'APP-DEMO-008',
    timestamp: '2026-09-11 22:52:12',
    source: 'Keycloak Auth Gateway',
    logType: 'APPLICATION',
    message: 'POST /api/v1/auth/login HTTP/1.1 200 OK - Successful Auth',
    rawData: '10.240.12.88 - admin [11/Sep/2026:22:52:12 +0000] "POST /api/v1/auth/login HTTP/1.1" 200 450 "https://corp.internal/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Identity & SSO Gateway',
      httpMethod: 'POST',
      endpoint: '/api/v1/auth/login',
      statusCode: 200,
      sourceIp: '10.240.12.88',
      userName: 'admin',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      payloadSnippet: 'username=admin&session_established=true'
    }
  },

  // 4. Unauthorized Access to Restricted Administrative Endpoints (403)
  {
    id: 'APP-DEMO-009',
    timestamp: '2026-09-11 22:52:20',
    source: 'API Gateway Envoy Proxy',
    logType: 'APPLICATION',
    message: 'GET /admin/config/secrets HTTP/1.1 403 Forbidden',
    rawData: '10.240.12.88 - admin [11/Sep/2026:22:52:20 +0000] "GET /admin/config/secrets HTTP/1.1" 403 310 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Core Management Console',
      httpMethod: 'GET',
      endpoint: '/admin/config/secrets',
      statusCode: 403,
      sourceIp: '10.240.12.88',
      userName: 'admin',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
    }
  },
  {
    id: 'APP-DEMO-010',
    timestamp: '2026-09-11 22:52:25',
    source: 'API Gateway Envoy Proxy',
    logType: 'APPLICATION',
    message: 'GET /api/internal/system/audit HTTP/1.1 403 Forbidden',
    rawData: '10.240.12.88 - admin [11/Sep/2026:22:52:25 +0000] "GET /api/internal/system/audit HTTP/1.1" 403 310 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Core Management Console',
      httpMethod: 'GET',
      endpoint: '/api/internal/system/audit',
      statusCode: 403,
      sourceIp: '10.240.12.88',
      userName: 'admin',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
    }
  },

  // 5. API Misuse & Excessive Rate Limit Violations (429)
  {
    id: 'APP-DEMO-011',
    timestamp: '2026-09-11 22:54:01',
    source: 'Kong API Gateway',
    logType: 'APPLICATION',
    message: 'POST /api/v1/data/export HTTP/1.1 429 Too Many Requests',
    rawData: '203.0.113.88 - - [11/Sep/2026:22:54:01 +0000] "POST /api/v1/data/export HTTP/1.1" 429 180 "-" "Go-http-client/1.1"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Data Analytics API Gateway',
      httpMethod: 'POST',
      endpoint: '/api/v1/data/export',
      statusCode: 429,
      sourceIp: '203.0.113.88',
      userAgent: 'Go-http-client/1.1',
      payloadSnippet: '{"exportFilter": "*", "format": "json"}'
    }
  },
  {
    id: 'APP-DEMO-012',
    timestamp: '2026-09-11 22:54:02',
    source: 'Kong API Gateway',
    logType: 'APPLICATION',
    message: 'POST /api/v1/data/export HTTP/1.1 429 Too Many Requests',
    rawData: '203.0.113.88 - - [11/Sep/2026:22:54:02 +0000] "POST /api/v1/data/export HTTP/1.1" 429 180 "-" "Go-http-client/1.1"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Data Analytics API Gateway',
      httpMethod: 'POST',
      endpoint: '/api/v1/data/export',
      statusCode: 429,
      sourceIp: '203.0.113.88',
      userAgent: 'Go-http-client/1.1',
      payloadSnippet: '{"exportFilter": "*", "format": "json"}'
    }
  },

  // 6. Automated Directory / Config File Fuzzing (404 scanning)
  {
    id: 'APP-DEMO-013',
    timestamp: '2026-09-11 22:54:30',
    source: 'Nginx Ingress Proxy',
    logType: 'APPLICATION',
    message: 'GET /.env HTTP/1.1 404 Not Found',
    rawData: '198.51.100.44 - - [11/Sep/2026:22:54:30 +0000] "GET /.env HTTP/1.1" 404 162 "-" "gobuster/3.5"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Public Web Frontend',
      httpMethod: 'GET',
      endpoint: '/.env',
      statusCode: 404,
      sourceIp: '198.51.100.44',
      userAgent: 'gobuster/3.5'
    }
  },
  {
    id: 'APP-DEMO-014',
    timestamp: '2026-09-11 22:54:31',
    source: 'Nginx Ingress Proxy',
    logType: 'APPLICATION',
    message: 'GET /.git/config HTTP/1.1 404 Not Found',
    rawData: '198.51.100.44 - - [11/Sep/2026:22:54:31 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "gobuster/3.5"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Public Web Frontend',
      httpMethod: 'GET',
      endpoint: '/.git/config',
      statusCode: 404,
      sourceIp: '198.51.100.44',
      userAgent: 'gobuster/3.5'
    }
  },
  {
    id: 'APP-DEMO-015',
    timestamp: '2026-09-11 22:54:32',
    source: 'Nginx Ingress Proxy',
    logType: 'APPLICATION',
    message: 'GET /actuator/health HTTP/1.1 404 Not Found',
    rawData: '198.51.100.44 - - [11/Sep/2026:22:54:32 +0000] "GET /actuator/health HTTP/1.1" 404 162 "-" "gobuster/3.5"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Public Web Frontend',
      httpMethod: 'GET',
      endpoint: '/actuator/health',
      statusCode: 404,
      sourceIp: '198.51.100.44',
      userAgent: 'gobuster/3.5'
    }
  },

  // 7. Internal Server Error Triggered by Request (500)
  {
    id: 'APP-DEMO-016',
    timestamp: '2026-09-11 22:55:00',
    source: 'Order Processing Microservice',
    logType: 'APPLICATION',
    message: 'POST /api/v2/checkout HTTP/1.1 500 Internal Server Error - Unhandled NullPointerException',
    rawData: '192.168.1.105 - - [11/Sep/2026:22:55:00 +0000] "POST /api/v2/checkout HTTP/1.1" 500 1204 "https://corp.internal/checkout" "python-requests/2.31.0"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Billing & Checkout Service v2',
      httpMethod: 'POST',
      endpoint: '/api/v2/checkout',
      statusCode: 500,
      sourceIp: '192.168.1.105',
      userAgent: 'python-requests/2.31.0',
      payloadSnippet: '{"cartId": "482", "coupon": "\' OR 1=1--"}'
    }
  },

  // 8. Normal Benign Traffic
  {
    id: 'APP-DEMO-017',
    timestamp: '2026-09-11 22:50:10',
    source: 'Nginx Ingress Proxy',
    logType: 'APPLICATION',
    message: 'GET / HTTP/1.1 200 OK',
    rawData: '172.16.0.4 - - [11/Sep/2026:22:50:10 +0000] "GET / HTTP/1.1" 200 8420 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Public Web Frontend',
      httpMethod: 'GET',
      endpoint: '/',
      statusCode: 200,
      sourceIp: '172.16.0.4',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }
  },
  {
    id: 'APP-DEMO-018',
    timestamp: '2026-09-11 22:50:15',
    source: 'Nginx Ingress Proxy',
    logType: 'APPLICATION',
    message: 'GET /api/v1/products HTTP/1.1 200 OK',
    rawData: '172.16.0.4 - - [11/Sep/2026:22:50:15 +0000] "GET /api/v1/products HTTP/1.1" 200 15420 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Catalog Microservice',
      httpMethod: 'GET',
      endpoint: '/api/v1/products',
      statusCode: 200,
      sourceIp: '172.16.0.4',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }
  },
  {
    id: 'APP-DEMO-019',
    timestamp: '2026-09-11 22:50:20',
    source: 'Nginx Ingress Proxy',
    logType: 'APPLICATION',
    message: 'GET /static/css/main.css HTTP/1.1 200 OK',
    rawData: '172.16.0.4 - - [11/Sep/2026:22:50:20 +0000] "GET /static/css/main.css HTTP/1.1" 200 4200 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'Static Asset CDN',
      httpMethod: 'GET',
      endpoint: '/static/css/main.css',
      statusCode: 200,
      sourceIp: '172.16.0.4',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }
  },
  {
    id: 'APP-DEMO-020',
    timestamp: '2026-09-11 22:50:30',
    source: 'Nginx Ingress Proxy',
    logType: 'APPLICATION',
    message: 'GET /api/v1/user/profile HTTP/1.1 200 OK',
    rawData: '172.16.0.4 - dev_sarah [11/Sep/2026:22:50:30 +0000] "GET /api/v1/user/profile HTTP/1.1" 200 1200 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    format: 'SYSLOG',
    normalizedFields: {
      applicationName: 'User Profile Service',
      httpMethod: 'GET',
      endpoint: '/api/v1/user/profile',
      statusCode: 200,
      sourceIp: '172.16.0.4',
      userName: 'dev_sarah',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }
  }
];
