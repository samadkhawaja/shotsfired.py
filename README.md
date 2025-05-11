# shotsfired.py
A Python script demonstrating exploitation of a GET parameter handling flaw in DVWA's High Level CSRF protection to change passwords.
# shotsfired.py 💥

**A Python tool to demonstrate and exploit the parameter handling vulnerability in DVWA's High Level Cross-Site Request Forgery (CSRF) protection.**

---

## Table of Contents

*   [Overview](#overview)
*   [The Vulnerability Explained (DVWA High CSRF)](#the-vulnerability-explained-dvwa-high-csrf)
*   [How `shotsfired.py` Works](#how-shotsfiredpy-works)
*   [Features](#features)
*   [Prerequisites](#prerequisites)
*   [Installation](#installation)
*   [Usage](#usage)
*   [Example Output](#example-output)
*   [Disclaimer](#disclaimer)
*   [License](#license)

---

## Overview

`shotsfired.py` is an educational tool designed to automate the process of changing a user's password on the Damn Vulnerable Web Application (DVWA) when the security level is set to 'High'.

While DVWA's High level CSRF protection correctly implements session-bound, rotating CSRF tokens (`user_token`), it contains a specific implementation flaw: it expects the critical password change parameters (`password_new`, `password_conf`, `Change`) via **GET** request parameters. However, it correctly reads the CSRF token from the **POST** request body (via PHP's `$_REQUEST` superglobal).

This script leverages this flaw by crafting a hybrid HTTP request (POST method with parameters in both the URL query string and the POST body) to bypass the intended protection.

---

## The Vulnerability Explained (DVWA High CSRF)

1.  **Valid Token Required:** The server generates a unique `user_token` for each session and page load, embedding it in a hidden form field.
2.  **Token Check:** Upon submission, the server checks if the submitted `user_token` (read via `$_REQUEST['user_token']`) matches the token stored in the session (`$_SESSION['session_token']`). This part works correctly.
3.  **POST Method Expected:** The HTML form for password change uses `method="POST"`.
4.  **The Flaw:** Despite the form using POST, the server-side PHP code **incorrectly** reads the actual password parameters (`password_new`, `password_conf`) and the submit action flag (`Change`) directly from the `$_GET` superglobal array.
5.  **Exploitation:**
    *   A standard POST request (sending all parameters, including passwords, in the POST body) fails because the server-side logic doesn't find `password_new`, `password_conf`, or `Change` in `$_GET`.
    *   `shotsfired.py` exploits this by:
        *   Sending the overall request using the **POST** method.
        *   Placing the valid `user_token` in the **POST body** (where `$_REQUEST` can find it).
        *   Placing the `password_new`, `password_conf`, and `Change` parameters in the **URL's query string (as GET parameters)** (where `$_GET` expects them).

This hybrid request satisfies both the token check (via `$_REQUEST` reading the POST body) and the flawed parameter reading logic (via `$_GET` reading the URL).

---

## How `shotsfired.py` Works

1.  **Session Management:** Uses `requests.Session` to maintain the necessary `PHPSESSID` and `security=high` cookies, simulating a logged-in user.
2.  **Token Fetching:** Sends a GET request to the DVWA CSRF page to retrieve the latest `user_token` using regular expressions.
3.  **Hybrid Request Crafting:**
    *   Constructs the target URL by appending `?password_new=...&password_conf=...&Change=Change` using the desired new password.
    *   Prepares a POST request body containing *only* the fetched `user_token`.
4.  **Submission:** Sends a POST request to the crafted URL with the token in the body.
5.  **Response Validation:** Checks the response content for the "Password Changed." success message or known error indicators.
6.  **Retry Logic:** Automatically retries the entire fetch-and-submit process up to a defined number of times (`MAX_RETRIES`) if the submission fails. This handles cases where the token might expire or rotate between fetching and submission.
7.  **Proxy Support:** Includes configuration to route traffic through a local proxy like Burp Suite (default: `http://127.0.0.1:8080`) for observation and debugging.

---

## Features

*   Authenticates using provided session cookies.
*   Automatically fetches the latest CSRF token for each attempt.
*   Exploits the GET parameter flaw in DVWA High Level CSRF.
*   Handles token rotation/expiry via an auto-retry mechanism.
*   Configurable target URL, new password, and session ID.
*   Optional proxy support for Burp Suite integration.
*   Clear console output for status and results.

---

## Prerequisites

*   Python 3.x
*   `requests` library (`pip install requests`)
*   A running instance of DVWA accessible from where you run the script.
*   DVWA security level set to **High**.
*   A **valid `PHPSESSID` cookie value** from an active, logged-in DVWA session.
*   (Optional) Burp Suite or another proxy running on `127.0.0.1:8080` if proxy usage is desired.

---

## Installation

1.  Clone the repository or download `shotsfired.py`:
    ```bash
    git clone https://github.com/samadkhawaja/shotsfired.py
    cd shotsfired
    ```
    (Or just download the `shotsfired.py` file directly)

2.  Install the required Python library:
    ```bash
    pip install requests
    ```

---

## Usage

1.  **Configure `shotsfired.py`:** Open the script in a text editor and modify the following configuration variables at the top:

    *   `TARGET_URL`: Set this to the exact URL of the CSRF vulnerability page in *your* DVWA instance (e.g., `http://127.0.0.1/vulnerabilities/csrf/` or `http://localhost/DVWA/vulnerabilities/csrf/`).
    *   `SESSION_COOKIE`: **⚠️ CRITICAL!** Replace the placeholder value with your current, valid `PHPSESSID` cookie value.
        *   *How to get PHPSESSID:*
            1.  Log into DVWA in your browser.
            2.  Open Developer Tools (usually F12).
            3.  Go to the 'Storage' (Firefox) or 'Application' (Chrome) tab.
            4.  Find Cookies for your DVWA domain (e.g., `127.0.0.1` or `localhost`).
            5.  Copy the **Value** of the `PHPSESSID` cookie.
    *   `NEW_PASSWORD`: Set the desired new password you want to change to.
    *   `proxies`: Adjust if your Burp Suite proxy runs on a different address or port. Set to `None` or an empty dictionary `{}` to disable the proxy.

2.  **Run the Script:** Execute the script from your terminal:
    ```bash
    python shotsfired.py
    ```

3.  **Observe Output:** The script will print its progress: attempting to fetch tokens, submitting requests, and the final success or failure message.

4.  **(Optional) Monitor in Burp Suite:** If using the proxy, check Burp's `Proxy` > `HTTP history` tab. You will see:
    *   `GET` requests to `/vulnerabilities/csrf/` (to fetch the token).
    *   `POST` requests where the URL includes the password GET parameters (`...?password_new=...&password_conf=...&Change=Change`) and the POST body contains the `user_token`.

---

## Example-Output (Success)

---

## Disclaimer

This tool is intended solely for **educational purposes** and for use in authorized security testing environments (e.g., your own DVWA instance). Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The author assumes no liability and is not responsible for any misuse or damage caused by this script.
