# Load tests

These scripts are intended for k6. They assume a running AuthKit instance and,
where required, pre-provisioned test data.

Set `BASE_URL` to the AuthKit origin, for example:

```sh
k6 run -e BASE_URL=http://localhost:3000 load-tests/login.js
```
