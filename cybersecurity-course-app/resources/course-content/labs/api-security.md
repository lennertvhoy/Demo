# API Security

**Objectives**

- Understand common API security vulnerabilities
- Learn techniques to secure RESTful APIs

**Exercises**

1. Implement token-based authentication using Laravel Sanctum.
2. Test for broken object-level authorization using a REST client.

**Code Snippet**

```php
// routes/api.php
Route::middleware('auth:sanctum')
    ->get('/user', function (Request $request) {
        return $request->user();
    });
```

**Challenges**

- Discover and exploit a broken function-level authorization in a sample API.
- Secure an API against rate limiting attacks. 