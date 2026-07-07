# BTLO Investigation Walkthrough — Phishy V1

**Scenario:** A phishing link was sent to a victim. The threat actor didn't know
who they were dealing with. Using only the phishing link, this walkthrough
traces the kit back to the actor and answers all 8 investigation questions.

Tools used: Web Browser, Text Editor, Linux CLI

---

## Q1 — Where was the decoy webpage mirrored from, and what tool was used?

Visiting the root of `securedocument.net` redirects to `/cgi-sys/`, which
displays a generic **"SORRY!"** default cPanel error page. This is a decoy —
it's meant to make the domain look like an unconfigured/parked hosting
account so it doesn't draw attention.

![Initial phishing page source with collapsed elements](screenshots/q1part1.png)

Viewing the page source of this default page reveals an HTML comment left
behind by the mirroring tool:

```html
<!-- Mirrored from 61.221.12.26/cgi-sys/defaultwebpage.cgi by HTTrack Website Copier/3.x [XR&CO'2014], Thu, 18 Feb 2021 12:43:50 GMT -->
```

![HTTrack mirror comment revealing source IP and tool](screenshots/qpart2.png)

**Answer:** `61.221.12.26/cgi-sys/defaultwebpage.cgi, HTTrack`

---

## Q2 — Full URL of the background image on the phishing landing page

Browsing to `http://securedocument.net/secure/` shows a directory listing
containing `0ff1cePh1sh.zip` and a `L0GIN/` folder. Following the folder
structure down to the actual phishing form:

```
http://securedocument.net/secure/L0GIN/protected/login/portal/index1.html
```

Viewing the source of `index1.html` (the real credential-harvesting page,
distinct from the `securedocument.net/cgi-sys` decoy) shows a linked
stylesheet, `style.css`. Inside that stylesheet is the background image
declaration:

![style.css showing the background image reference](screenshots/q2.png)

```css
body {
    background: url('axCBhIt.png') no-repeat fixed;
    ...
}
```

Resolving that relative path against the page's actual location gives the
full URL.

**Answer:** `http://securedocument.net/secure/L0GIN/protected/login/portal/axCBhIt.png`

---

## Q3 — Name of the PHP page that processes stolen credentials

The login form on `index1.html` posts to:

```html
<form action="jeff.php" method="post">
```

This is also confirmed in the browser's Network tab — after submitting the
form, `jeff.php` is shown as the initiator of the follow-up request to
`www.office.com`:

![Network tab showing jeff.php as initiator and the office.com request](screenshots/q3and7.png)

**Answer:** `jeff.php`

---

## Q4 — SHA256 of the phishing kit ZIP (last 6 characters)

The phishing kit archive `0ff1cePh1sh.zip` was found sitting in a directory
listing at `/secure/`:

![Directory listing showing 0ff1cePh1sh.zip and LOGIN folder](screenshots/q4part1.png)

Hashing it on the Linux CLI:

```bash
$ sha256sum 0ff1cePh1sh.zip
c778236f4a731411ab2f8494eb5229309713cc7ead44922b4f496a2032fa5b48  0ff1cePh1sh.zip
```

![Terminal output of sha256sum on the phishing kit zip](screenshots/q4part2.png)

**Answer:** `fa5b48`

---

## Q5 — Email address set up to receive credential logs

Inside `jeff.php`, the recipient variable is set directly:

```php
$recipient = "boris.smets@tfl-uk.co";
```

![jeff.php recipient variable](screenshots/q5.png)

**Answer:** `boris.smets@tfl-uk.co`

---

## Q6 — Function that produces the PHP variable in the index1.html URL

The site's initial `index.html` doesn't load `index1.html` directly — it
appends a value to the URL using JavaScript:

```html
<script language=javascript>
window.location='index1.html?'+new Date().getTime();
</script>
```

![View-source showing the getTime() redirect script](screenshots/q6.png)

This value (a timestamp) becomes the `$datamasii` variable referenced back
in `jeff.php`.

**Answer:** `getTime()`

---

## Q7 — Domain the victim should land on after entering credentials

At the bottom of `jeff.php`, after the credentials are emailed off, the
victim is redirected:

```php
$result = "office";
...
window.location='https://www.office.com';
```

![Full view-source of index1.html phishing form](screenshots/q7part1.png)

![Full view-source of jeff.php processing script](screenshots/q7part2.png)

Confirmed in the browser Network tab as well (see Q3 screenshot above) —
after submission, a GET request goes out to `www.office.com`.

**Answer:** `office.com`

---

## Q8 — Broken variable name causing the phishing kit to fail

Comparing the HTML form fields in `index1.html` against what `jeff.php`
actually expects via `$_POST`:

**`index1.html` (form field names):**
```html
<input type="email" name="userrr" placeholder="Email ID" required>
<input type="password" name="passss" placeholder="Email Password" required>
```

**`jeff.php` (expected POST variables):**
```php
$message .= "User : ".$_POST['user1']."\n";
$message .= "Password: " .$_POST['pass1']."\n";
```

The form sends `userrr` / `passss`, but the PHP script expects `user1` /
`pass1`. Because none of these match, `$_POST['user1']` and
`$_POST['pass1']` are always empty — the credentials are silently lost and
the kit never actually captures anything, despite the victim being
redirected to `office.com` as if it worked.

**Answer (any one accepted):** `pass1` (also valid: `userrr`, `user1`, `passss`)

---

## Summary

| # | Question | Answer |
|---|----------|--------|
| 1 | Mirror source + tool | `61.221.12.26/cgi-sys/defaultwebpage.cgi, HTTrack` |
| 2 | Background image URL | `http://securedocument.net/secure/L0GIN/protected/login/portal/axCBhIt.png` |
| 3 | Credential-stealing PHP page | `jeff.php` |
| 4 | ZIP SHA256 (last 6 chars) | `fa5b48` |
| 5 | Recipient email | `boris.smets@tfl-uk.co` |
| 6 | JS/PHP timestamp function | `getTime()` |
| 7 | Post-login redirect domain | `office.com` |
| 8 | Broken/mismatched variable | `pass1` (or `userrr` / `user1` / `passss`) |
