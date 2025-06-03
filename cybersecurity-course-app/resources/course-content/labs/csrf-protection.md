# CSRF Protection

**Objectives**

- Learn what CSRF attacks are and how they work
- Implement CSRF protection in Laravel forms and APIs

**Exercises**

1. Create a Laravel form without CSRF protection and demonstrate an attack.
2. Fix the form by adding `@csrf` directives and test again.

**Code Snippet**

```html
<form action="/submit" method="POST">
    @csrf
    <input type="text" name="data" />
    <button type="submit">Submit</button>
</form>
```

**Challenges**

- Craft and execute a CSRF attack on a sample application.
- Implement CSRF protection for state-changing API routes. 