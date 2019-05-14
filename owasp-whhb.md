# Intro

Legend
```
X - NOT VULNERABLE
V - VULNERABLE
N - NOT APPLICABLE
- - NOT TESTED
```

# RECON

id: 1

## Browser entire application while in burp

id: 1.1

* URL:
* Username:
* Password:


## Consult Public Sources

id: 1.2

* [ ] Google

```
site:target.com filetype:7z OR filetype:bin OR filetype:bzip2 OR 
filetype:egg OR filetype:gzip OR filetype:rar OR filetype:zip OR 
filetype:iso OR filetype:dat OR filetype:db OR filetype:sql OR 
filetype:indd OR filetype:psd OR filetype:asc OR filetype:csv OR 
filetype:docx OR filetype:doc OR filetype:epub 
    
Google limit the number of letters in a query so we need to divide it up in several chunks
site:target.com filetype:html OR filetype:htm OR filetype:gdoc OR
filetype:log OR filetype:md OR filetype:odt OR filetype:rtf OR
filetype:odf OR filetype:php OR filetype:ods OR filetype:xls OR
filetype:xlsx OR filetype:conf OR filetype:cnf OR filetype:cfg OR
filetype:temp OR filetype:tmp OR filetype:ppt OR
filetype:txt
    
site:target.com filetype:java OR filetype:bak OR filetype:old OR
filetype:tar OR filetype:rar OR filetype:tgz OR filetype:gz

site:target.com filetype:pdf
```

* [ ] https://web.archive.org/
* [ ] https://yahoo.com
* [ ] https://bing.com
* [ ] https://netcraft.com/


## Discover Hidden Content

id: 1.3

* [ ] Review comments and other client side code to find hidden content
* [ ] Sample files, known files
      - dirb https://www.address.blab -f -l -R -z 10 -o address.blab.txt
* [ ] Run it targeting the IP address directly

## Discover DNS

* [ ] Reverse DNS lookup
`dig -x 10.10.10.10`
* [ ] Brute force DNS (recon-ng, recon/domain-hosts/brute-hosts, set source, show hosts)
* [ ] python sublist3r.py -d example.com
* [ ] Zone-transfer test (fierce -dns target.com)


## Enumerate Identifier-Specified Functions

id: 1.5

* [ ] Identify instances where specific functions are accessed by url parameters
      Example: /admin.jsp?action=editUser
* [ ] Fuzz those for other actions

----------------------------------------------------------------------------

# Analyze the Application

## Identify Functionality

* [ ] Core Functionality
* [ ] Security Functionality 
* [ ] Peripheral Functionality (error messages, administratice, logging-functionality)
* [ ] Functionality that diverge from standard GUI appearance, parameter naming, navigation mechanism

## Identify Data Entry Points

POST, GET, WS?

* [ ] Identify the Technologies Used
* [ ] Client side (cookies, scripts, java applets, flash)
* [ ] Server side (server, scripting lang, platform, backend components)
* [ ] Map the Attack Surface
* [ ] Acertain likely internal structure
* [ ] Identify vulnerabilities related to each functionality
* [ ] Formulate plan to attack - Prioritize 

----------------------------------------------------------------------------

# Basic tests

* [ ] Check Same-Origin Policy Configuration
* [ ] Check for presence of Headers:
  Expires, Cache-control: no-cache, Pragma, HSTS
* [ ] Check for /crossdomain.xml
* [ ] Check /clientaccesspolicy.xml
* [ ] Check for Local Privacy Vulnerabilities



# Static analysis of JavaScript


* [ ] Increase attack surface by looking for URL:s and domains
* [ ] Sensitive information (Passwords, API keys, Storage etc)
* [ ] Potentially dangerous areas in code(eval, dangerouslySetInnerHTML etc)
* [ ] Components with known vulnerabilities (Outdated frameworks etc)


##  Test Transmission of Data Via the Client

* [ ] Locate hidden fields, cookies and URL parameters
* [ ] Try to deobfuscate obfuscated data (like viewState or other)
* [ ] Identify Client-Side Controls Over User Input
* [ ] Test if the controls are replicated on server-side
* [ ] Looked for disabled content. `input disabled=true`
* [ ] Test Browser Extension Components (flash, java-applet, etc)


----------------------------------------------------------------------------




# Test the Autentication Mechanism

id: 4.0


## Test Login Mechanism
* [ ] Test for Logic Flaws
* [ ] Test for Fail-Open Conditions
    * [ ] Test to submit empty string as the value
    * [ ] Remove the name/value pair
    * [ ] Submit very long and very short values
    * [ ] Submit strings instead of numbers, and vice versa
    * [ ] Submit the same named parameter multiple times, with the same and different values
* [ ] Test any Multistage Mechanisms
    * [ ] Proceed through all stages but in different sequence
* [ ] Test Resilience to Password Guessing - Lock-out mechanism
* [ ] Test Any Impersionation Function
* [ ] Test for Username Enumeration
* [ ] Testing for default credentials (OTG-AUTHN-002) 

### If Saml SSO
https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/
* [ ] Identify Saml Response (Response from IDP to SP)
* [ ] Test if message expiration is honored (<Saml:Condition NotBefore="2018-01-01T12:00")
* [ ] Test if SP allows replay. SP should only allow response once. Test if you can send it multiple times.
* [ ] Test if message contains a signature (it should)
* [ ] Ensure certificate is signed by real and trusted CA (not self-signed)
* [ ] If not signed by trusted CA, try cloning it.
* [ ] Test SAML Response from different Recipient
* [ ] Signature Wrapping attacks
    * [ ] Test XSW1 – Applies to SAML Response messages. Add a cloned unsigned copy of the Response after the existing signature.
    * [ ] Test XSW2 – Applies to SAML Response messages. Add a cloned unsigned copy of the Response before the existing signature.
    * [ ] Test XSW3 – Applies to SAML Assertion messages. Add a cloned unsigned copy of the Assertion before the existing Assertion.
    * [ ] Test XSW4 – Applies to SAML Assertion messages. Add a cloned unsigned copy of the Assertion after the existing Assertion.
    * [ ] Test XSW5 – Applies to SAML Assertion messages. Change a value in the signed copy of the Assertion and adds a copy of the original Assertion with the signature removed at the end of the SAML message.
    * [ ] Test XSW6 – Applies to SAML Assertion messages. Change a value in the signed copy of the Assertion and adds a copy of the original Assertion with the signature removed after the original signature.
    * [ ] Test XSW7 – Applies to SAML Assertion messages. Add an “Extensions” block with a cloned unsigned assertion.
    * [ ] Test XSW8 – Applies to SAML Assertion messages. Add an “Object” block containing a copy of the original assertion with the signature removed.
* [ ] Test for comment in <Subject> - https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
* [ ] Test for XXE

## Test Registration Mechanism
* [ ] Test Password Quality [[OTG-AUTHN-007]]
* [ ] Test for Username Enumeration
* [ ] Test Username Uniqueness
* [ ] Register same usernname twice (if it is blocked, you can use it to enumerare users). If second account is create, test what happens with collisions.
* [ ] Test Predictibility of Autogenerated Credentials If usernames and passwords are autogenerated see if they are generated in a predictable way.
* [ ] Check for Unsafe Transmission of Credentials
* [ ] Check for Unsafe Distribution of Credentials (Send over email)
* [ ] If application use activation-email with URL test how the URLs are created.
* [ ] Test for Insecure Storage
* [ ] Testing for Weak security question/answer (OTG-AUTHN-008)

## Test two factor authentication (2fa)
* [ ] Check 2fa

## Password reset mechanism
* [ ] Testing for weak password change or reset functionalities (OTG-AUTHN-009)
* [ ] Check if password reset token can be used several times
* [ ] Check if sessions are invalidated when password is reset
* [ ] Check for user enumeration
* [ ] Check that password is not sent in cleartext
* [ ] Check that password reset token is of high entropy
* [ ] Check that password reset token is unique, random
* [ ] Check that lifespan of the password reset token (Max 24 hours)
* [ ] Check that there is not link to external page where token is sent in referer header

## Other Tests
* [ ] Test Any Remember Me/Password Function
* [ ] Testing for Browser cache weakness (OTG-AUTHN-006)
* [ ] Testing for Weaker authentication in alternative channel (OTG-AUTHN-010)

----------------------------------------------------------------------------

# Test the Session Management Mechnaism

id: 5

* [ ] Understand the Session Mechanism

If cookie:
* [ ] Identify which token is the session identification
* [ ] Test Tokens for Meaning
* [ ] Log in with several usernames and record the tokens recieved. Name the users stuff like A, AA, AAA, AAAAA, AAAAB
* [ ] Analyze token for obfuscation or encoding (base64 etc)
* [ ] Test Tokens for Predictibility
* [ ] Generate and capture a large amount of session tokens
* [ ] Try to identify any patterns
* [ ] If the Session ID is custom-written, use the bit-flipper in burp.
* [ ] Check for Insecure Transmission of Tokens
* [ ] Check for Disclosure of Tokens in Logs
* [ ] Check Mapping of Tokens to Sessions
* [ ] Check if session is terminated on the server side when a user logs out
* [ ] Check when cookies expire, if it is in the future the session will be alive until it expires.

If JWT:
See: https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/
https://www.ticarpi.com/jwt-tool-attack-methods/
* [ ] Test changing alg value to none/None - remove the signature but keep the dot
* [ ] Test to change RS256 to HS256
* [ ] Test for weak secret - brute force secret key

## Test for Session Fixation (OTG-SESS-003)
* [ ] Check if sessionID is set before user is authenticated
  If the sessionID is not set to authenticated users you can log in with one user, and then go to login-page again, andtv log in with another user. If no new session-token is issued it is vulnerable to session fixation.

## Test for CSRF (OTG-SESS-005)
* [ ] If the app uses CSRF-tokens, test the robustness of those. Can you just use whatever?
* [ ] Check Cookie Scope

----------------------------------------------------------------------------

# Test Access Controls

id: 6.0

* [ ] Check vertical access control - identify admin functions and resources. Check if non-admin can access them. (OTG-AUTHZ-003)
* [ ] Check horizontal access control - try to reach resources from other user at same level.
* [ ] Check if you can use token/cookie generated on one application in another (if testing various applications talking with the same api) 
* [ ] Test for Insecure Access Control Methods
* [ ] Testing for Insecure Direct Object References (OTG-AUTHZ-004)
* [ ] Look out for control methods like access=read, edit=false.
* [ ] Some access control is based on Referer.
* [ ] Try crafting HTTP requests that send data with HEAD/CATS method instead of GET.

----------------------------------------------------------------------------

# Test for Input-Based Vulnerabilities

id: 7.0

Start looking for injections by doing a basic first fuzzing. Analyze the outcome of it.
It is a good idea to use Burps fuzzing-list, but make sure to edit it before.


* [ ] Test for SQL Injection
http://rextester.com/l/sql_server_online_compiler
* [ ] Test to submit single and double quotation-marks.
* [ ] Test for XSS and Other Response Injections
* [ ] Test for Reflected XSS (OTG-INPVAL-001)
    * [ ] Check for parameters. Burp/Analyze target/parameters
* [ ] Test for HTTP Header Injection
* [ ] Test for HOST-header manipulation (att two host headers, add X-Forwarded-Host) If you can, see: https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html
* [ ] Test for Open Redirection
* [ ] Test for Stored Attacks
* [ ] Test for OS Command Injection
* [ ] Test for Path Traversal
* [ ] Test for Script Injection
* [ ] Test for File Inclusion
* [ ] Testing for HTTP Parameter pollution (OTG-INPVAL-004)
* [ ] Testing for NoSQL injection
* [ ] Testing for XML Injection (OTG-INPVAL-008)
* [ ] If application is creating spreadsheet test for CSV injection

----------------------------------------------------------------------------


# Testing for weak Cryptography

* [ ] Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection (OTG-CRYPST-001)
    * [ ] RSA Public Key bits:
    * [ ] Issuer:
    * [ ] Signature Algorithm: 
* [ ] Testing for Padding Oracle (OTG-CRYPST-002)
* [ ] Testing for Sensitive information sent via unencrypted channels (OTG-CRYPST-003)

# Business Logic Testing

* [ ] Test Business Logic Data Validation (OTG-BUSLOGIC-001)
* [ ] Test Ability to Forge Requests (OTG-BUSLOGIC-002)
* [ ] Test Integrity Checks (OTG-BUSLOGIC-003)
* [ ] Test for Process Timing (OTG-BUSLOGIC-004)
* [ ] Test Number of Times a Function Can be Used Limits (OTG-BUSLOGIC-005)
* [ ] Testing for the Circumvention of Work Flows (OTG-BUSLOGIC-006)
* [ ] Test Defenses Against Application Mis-use (OTG-BUSLOGIC-007)

# Test file upload

* [ ] Test Upload of Unexpected File Types (OTG-BUSLOGIC-008)
* [ ] Test Upload of Malicious Files (OTG-BUSLOGIC-009)

# Client Side Testing

* [ ] Testing for DOM based Cross Site Scripting (OTG-CLIENT-001)
    * [ ] Identify the following APIs:
```
  document.location
  document.URL
  document.URLEncoded
  document.referrer
  window.location
```
    * [ ] Identify if any of the input data to above mentioned APIs are passed through the following functions:
```
  document.write()
  document.writeln()
  document.body.innerHtml
  eval()
  window.execScript()
  window.setInterval()
  window.setTimeout()
```
    * [ ] If the input data is passed through to any of the following functions it might be vulnerable to redirection attack:
```
  document.location
  document.URL
  document.open()
  window.location.href
  window.navigate()
  window.open()
```

* [ ] Testing for JavaScript Execution (OTG-CLIENT-002)
* [ ] Testing for HTML Injection (OTG-CLIENT-003)
* [ ] Testing for Client Side URL Redirect (OTG-CLIENT-004)
* [ ] Testing for CSS Injection (OTG-CLIENT-005)
* [ ] Testing for Client Side Resource Manipulation (OTG-CLIENT-006)
* [ ] Test Cross Origin Resource Sharing (OTG-CLIENT-007)
* [ ] Testing for Cross Site Flashing (OTG-CLIENT-008)
* [ ] Testing for Clickjacking (OTG-CLIENT-009)
* [ ] Testing WebSockets (OTG-CLIENT-010)
* [ ] Test Web Messaging (OTG-CLIENT-011)
* [ ] Test Local Storage (OTG-CLIENT-012)


# Test for Function-Specific Input Vulnerabilities

id 8.0

* [ ] Test for SMTP-injection
* [ ] Test for Native Software Vulnerabilities
* [ ] Test for Buffer Overflows
* [ ] Test for Integer Vulnerabilities
* [ ] Test for Format String Vulnerabilities
* [ ] Test for SOAP Injection
* [ ] Test for LDAP Injection
* [ ] Test for XPath Injection
* [ ] Test for Back-End Request Injection
* [ ] Test for XXE Injection (https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
	* [ ] If JSON, change the content type to application/xml, and change the body to xml format, and follow the link above.

----------------------------------------------------------------------------

# Test for Logic Flaws

id: 9.0

Identify the key attack surface
	    
* [ ] Test Multistage Processes
  Skip stages. Accessing one stage several times. Look for error messages and debug output.
* [ ] Test Handling of Incomplete Input
* [ ] Test Trust Boundaries
* [ ] Test Transaction Logic

----------------------------------------------------------------------------

# Test for Shared Hosting Vulnerabilities

id: 10.0

* [ ] Test Segregation in Shared Infrastructure
* [ ] Test Segregation Between ASP-Hosted Applications

----------------------------------------------------------------------------

# Test for Application Server Vulnerabilities

id: 11.0

* [ ] Perform a port-scan of machine to identify administrative interface
    * [ ] If found, test default credentials.
* [ ] Test for Default Content
* [ ] Scan with Nikto
* [ ] Examine default content found
* [ ] Test for Dangerous HTTP Methods (OTG-CONFIG-006)
    * [ ] Use OPTIONS-method to list HTTP Methods available on the server
    * [ ] Try each reported method and confirm them
    * [ ] Test for Proxy Functionality
    * [ ] Test for Virtual Hosting Misconfiguration
    * [ ] Send correct Host-header
    * [ ] Bogus Host-header
    * [ ] The servers ip-address in the host-header
    * [ ] No Host-header (use HTTP/1.0 only)
* [ ] Test for Web Server Software Bugs
* [ ] Run Nessus or similar
* [ ] Test for Web Application Firewalling

----------------------------------------------------------------------------


# Miscellaneous Checks

id: 12.0
* [ ] Information disclose / Stack trace

## Test for Debug Parameters

   id: 1.6

* [ ] Test debug=true in URLs

Use cluster-bomb attack in Burp

```
debug       true
test        yes
hide        1
source      on

----------------------------------------------------------------------------


# A little bit of everything

http://pentestmonkey.net/

http://sqlzoo.net

https://github.com/Hack-with-Github/Awesome-Hacking/blob/master/README.md

https://html5sec.org/

Various Cloud service SSRF endpoints https://gist.github.com/BuffaloWill/fa96693af67e3a3dd3fb

https://github.com/bl4de/security_whitepapers

## Notes
