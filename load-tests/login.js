import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 20 },
    { duration: '1m', target: 50 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<1000'],
  },
};

const baseUrl = __ENV.BASE_URL || 'http://localhost:3000';

export default function () {
  const response = http.post(
    `${baseUrl}/login`,
    'email=load-test%40example.com&password=load-test-password',
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );
  check(response, {
    'login handled': (r) => r.status === 200 || r.status === 303 || r.status === 429,
  });
  sleep(1);
}
