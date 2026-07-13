# vibe-audit security report

**Target:** ./my-project  
**Mode:** code  
**Date:** 2026-07-13  
**Score:** 0/100 (Grade F)  

## Summary

| Severity | Count |
|---|---|
| 🔴 Critical | 12 |
| 🟠 High | 2 |
| 🟡 Medium | 0 |
| 🔵 Low | 0 |
| ⚪ Info | 1 |

## Findings

### 1. Stripe live secret key found in source code

**Severity:** 🔴 Critical  
**Category:** secrets  
**Location:** `.env:2`  

A value matching the pattern for a Stripe live secret key was found hardcoded in the source code. If this file is ever committed to version control, the secret is compromised the moment it is pushed — even if the file is deleted afterwards, it stays in git history.

**Evidence (masked):** `sk_l************************XXXX`

```
STRIPE_SECRET_KEY=sk_l************************XXXX
```

**Recommendation:** Move this value to an environment variable (loaded via .env, which must stay in .gitignore) or a secrets manager, and rotate/revoke the exposed credential now since it may already be compromised.

### 2. database connection string with embedded credentials found in source code

**Severity:** 🔴 Critical  
**Category:** secrets  
**Location:** `.env:1`  

A value matching the pattern for a database connection string with embedded credentials was found hardcoded in the source code. If this file is ever committed to version control, the secret is compromised the moment it is pushed — even if the file is deleted afterwards, it stays in git history.

**Evidence (masked):** `post*******************************************************5432`

```
DATABASE_URL=post*******************************************************5432/prod
```

**Recommendation:** Move this value to an environment variable (loaded via .env, which must stay in .gitignore) or a secrets manager, and rotate/revoke the exposed credential now since it may already be compromised.

### 3. Stripe live secret key found in source code

**Severity:** 🔴 Critical  
**Category:** secrets  
**Location:** `server.js:8`  

A value matching the pattern for a Stripe live secret key was found hardcoded in the source code. If this file is ever committed to version control, the secret is compromised the moment it is pushed — even if the file is deleted afterwards, it stays in git history.

**Evidence (masked):** `sk_l************************XXXX`

```
const STRIPE_SECRET_KEY = "sk_l************************XXXX";
```

**Recommendation:** Move this value to an environment variable (loaded via .env, which must stay in .gitignore) or a secrets manager, and rotate/revoke the exposed credential now since it may already be compromised.

### 4. AWS access key ID found in source code

**Severity:** 🔴 Critical  
**Category:** secrets  
**Location:** `server.js:9`  

A value matching the pattern for a AWS access key ID was found hardcoded in the source code. If this file is ever committed to version control, the secret is compromised the moment it is pushed — even if the file is deleted afterwards, it stays in git history.

**Evidence (masked):** `AKIA************MPLE`

```
const AWS_ACCESS_KEY_ID = "AKIA************MPLE";
```

**Recommendation:** Move this value to an environment variable (loaded via .env, which must stay in .gitignore) or a secrets manager, and rotate/revoke the exposed credential now since it may already be compromised.

### 5. Sensitive file not excluded by .gitignore: .env

**Severity:** 🔴 Critical  
**Category:** gitignore  
**Location:** `.env`  

".env" looks like a environment file, but it is not covered by any .gitignore rule. If this repository is committed as-is, this file — and any secret inside it — will be pushed to version control.

**Recommendation:** Add an entry covering this file to .gitignore (for example ".env" or a matching pattern), then remove it from git history if it was already committed.

### 6. Table "profiles" created without Row Level Security

**Severity:** 🔴 Critical  
**Category:** database-rules  
**Location:** `supabase/migrations/0001_init.sql:2`  

Migration "supabase/migrations/0001_init.sql" creates a table named "profiles", but no migration enables Row Level Security on it. On Supabase, a table without RLS is readable and writable by anyone holding the public anon API key, regardless of who owns the row.

**Recommendation:** Add "ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;" plus explicit policies for the operations you actually want to allow (select/insert/update/delete), in a migration.

### 7. Table "orders" created without Row Level Security

**Severity:** 🔴 Critical  
**Category:** database-rules  
**Location:** `supabase/migrations/0001_init.sql:8`  

Migration "supabase/migrations/0001_init.sql" creates a table named "orders", but no migration enables Row Level Security on it. On Supabase, a table without RLS is readable and writable by anyone holding the public anon API key, regardless of who owns the row.

**Recommendation:** Add "ALTER TABLE orders ENABLE ROW LEVEL SECURITY;" plus explicit policies for the operations you actually want to allow (select/insert/update/delete), in a migration.

### 8. Firestore rule allows unrestricted access

**Severity:** 🔴 Critical  
**Category:** database-rules  
**Location:** `firestore.rules:4`  

"firestore.rules" contains a rule that unconditionally allows access ("allow read, write: if true;"). Any client, including unauthenticated ones, can read and/or write this data.

```
allow read, write: if true;
```

**Recommendation:** Scope the rule to authenticated, authorized requests, e.g. "allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;".

### 9. CORS allows any origin together with credentials

**Severity:** 🔴 Critical  
**Category:** cors  
**Location:** `server.js:12`  

This CORS configuration combines a wildcard/any origin with credentials enabled. Browsers already forbid this combination for real credentialed requests, so servers that accept it typically end up reflecting the request's Origin header — which lets any website read authenticated responses from this API on behalf of a logged-in visitor.

```
{ origin: "*", credentials: true }
```

**Recommendation:** List explicit allowed origins (e.g. your production domain and localhost for dev) instead of "*" or reflecting the request Origin, and only enable credentials for those explicit origins.

### 10. TLS certificate verification disabled (verify=False)

**Severity:** 🔴 Critical  
**Category:** dangerous-patterns  
**Location:** `app.py:10`  

This code disables TLS certificate verification for outgoing HTTPS requests, making the connection vulnerable to man-in-the-middle attacks.

```
return requests.get(url, verify=False)
```

**Recommendation:** Remove verify=False (or set it to True / a CA bundle path). If this was added to work around a certificate problem, fix the certificate instead.

### 11. SQL query built with an f-string

**Severity:** 🔴 Critical  
**Category:** dangerous-patterns  
**Location:** `app.py:14`  

A SQL statement is built with an f-string. If any interpolated value comes from user input, this is a classic SQL injection vulnerability.

```
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Recommendation:** Use your database driver's parameterized query syntax (e.g. cursor.execute(query, params)) instead of an f-string.

### 12. SQL query built with string concatenation

**Severity:** 🔴 Critical  
**Category:** dangerous-patterns  
**Location:** `server.js:17`  

A SQL statement is assembled with string concatenation. If any concatenated part comes from user input, this is a classic SQL injection vulnerability.

```
const query = "SELECT * FROM users WHERE id = " + userId;
```

**Recommendation:** Use parameterized queries / prepared statements instead of building SQL strings by hand.

### 13. Debug mode hardcoded to True

**Severity:** 🟠 High  
**Category:** dangerous-patterns  
**Location:** `app.py:6`  

Debug mode is hardcoded on. In frameworks like Flask/Django, debug mode can expose stack traces, source code, and in some configurations an interactive debugger that allows remote code execution if reachable in production.

```
DEBUG = True
```

**Recommendation:** Load DEBUG from an environment variable (e.g. os.environ.get("DEBUG") == "true") and make sure production deployments default to False.

### 14. Use of eval()

**Severity:** 🟠 High  
**Category:** dangerous-patterns  
**Location:** `server.js:23`  

eval() executes arbitrary strings as code. If any part of the evaluated string can be influenced by user input, this is a direct route to remote code execution.

```
const result = eval(req.body.expression);
```

**Recommendation:** Avoid eval() entirely. Use JSON.parse for data, or a proper parser for anything more complex.

### 15. pip-audit is not installed

**Severity:** ⚪ Info  
**Category:** dependencies  

This project has Python dependency files, but pip-audit is not available, so vibe-audit could not check them for known vulnerabilities.

**Recommendation:** Install pip-audit and run it as part of your workflow (or CI).
