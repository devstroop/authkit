import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 20 },
    { duration: '1m', target: 50 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.10'],
    http_req_duration: ['p(95)<500'],
  },
};

const baseUrl = __ENV.BASE_URL || 'http://localhost:3000';

export default function () {
  const response = http.post(
    `${baseUrl}/oauth2/token`,
    'grant_type=client_credentials&client_id=load-test&client_secret=load-test&scope=openid',
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );
  check(response, {
    'token endpoint handled': (r) => r.status === 200 || r.status === 400 || r.status === 401 || r.status === 429,
  });
  sleep(1);
}
