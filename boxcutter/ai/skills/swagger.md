# Swagger / OpenAPI spec

**Trigger:** swagger-specs found a spec (or you see a Swagger/OpenAPI UI).

**Action:** `swagger-endpoints` to MAP every operation, then WORK THE WHOLE LIST: `http-request` each UNAUTHENTICATED to see which need no auth; on any operation taking an object-id path/query param run the ID ENUMERATION play; flag test/debug ops; and FUZZ every endpoint (its `--fuzzable` variants).

**Confirm:** a spec is the full map of the API's real surface, so unauth operations returning data, enumerable objects, working test/debug ops, and injections are ALL findings - do NOT stop at "a spec exists".
