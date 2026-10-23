# PWNBoard Usage Guide
*Replace `pwnboard.win` in the examples with your PWNBoard domain (the `PWNBOARD_DOMAIN` it was deployed with)*

## Contents
- [Quick reference](#quick-reference)
- [Generate an access token for your tool](#generate-an-access-token-for-your-tool)
- [Sending callback data](#sending-callback-data-to-pwnboard)
- [Sending credential data](#sending-credential-data-to-pwnboard)
- [Responses](#responses)
- [Examples](#examples-of-posting-data-to-pwnboard) (curl, Bash beacon loop, Python, Go, PowerShell, C#)
- [Self-signed certificates](#self-signed-certificates)

## Quick reference

| What | Method and URL | Required fields |
|------|----------------|-----------------|
| Callback (beacon) | `POST https://pwnboard.win/pwn` (also `/checkin`) | `ip`, `application` |
| Credentials | `POST https://pwnboard.win/creds` | `ip`, `application`, `username`, `password` |

- The body is JSON, sent with `Content-Type: application/json`.
- If access tokens are enabled (the default), add the header `Authorization: Bearer <token>`.
- The `ip` must be one of the hosts on the PWNBoard, otherwise the request is rejected.
- Requests larger than 1 MB are rejected, and fields have length limits (see [Responses](#responses)).

## Generate an Access Token for your tool
To create an access token for your application:
1. Ask the admin to make a PWNBoard account for you. Accounts with the `guest` or `restricted` role cannot create tokens.
2. Click your username (top right) --> Manage Apps (`/manage_apps`) --> **+ Add Token**
3. Fill in the form:
   - **Token name**: any label for you to recognize the token by
   - **Application**: must match the `application` field your tool sends (not case sensitive). A token with the application name `global` works for every application
   - **Expiry**: defaults to 7 days. Choose "No expiry" for a token that should never stop working
4. Copy and save the created token. It is shown only once, so you will not be able to see it again

If the admin disabled access tokens (`USE_ACCESS_TOKENS=false`), you do not need a token and can leave out the `Authorization` header. The Manage Apps page shows whether token verification is currently on.

## Sending callback data to PWNBoard
POST data in this format to https://pwnboard.win/pwn :
### Minimum Required Parameters
`{"ip": "<ip>", "application": "<your tool>"}`

### Optional Parameters
`{"ip": "<ip>", "application": "<your tool>", "access_info": "<optional information to access this tool (URL, creds, etc.)>" }`

`access_info` is shown in the host's popup on the dashboard, and any URLs in it become clickable links.

### Several hosts in one request
To report callbacks for multiple hosts at once, send a list in `ips` instead of `ip`:

`{"ips": ["<ip 1>", "<ip 2>"], "application": "<your tool>"}`

If one of the IPs is not on the PWNBoard, the request returns `400`. IPs listed before it were already accepted.

### How callbacks show up
A host counts as online for `HOST_TIMEOUT` minutes after its last callback (5 by default), so send callbacks more often than that. New data typically appears on the dashboard within about 15 seconds.

## Sending credential data to PWNBoard
POST data in this format to https://pwnboard.win/creds :
### Minimum Required Parameters
`{"ip": "<ip>", "application": "<application>", "username": "<username>", "password": "<password>"}`

### Optional Parameters
`{"ip": "<ip>", "application": "<application>", "username": "<username>", "password": "<password>", "admin": <0 or 1>}`

`admin` must be `0` or `1` if it is included. `ips` works here as well.

Passwords that are one character or shorter are ignored. Credentials count as active for `CREDS_TIMEOUT` minutes (30 by default) after they were last received. After that they stay in the host's popup, marked **stale**, since the password may still work.

## Responses

| Status | Body | Meaning |
|--------|------|---------|
| `200` | `valid` | The request was accepted and queued. It shows up on the board shortly after |
| `400` | `invalid IP` | The `ip` is not on this PWNBoard (a wrong or unexpected address is the usual cause) |
| `400` | `invalid POST` | The body has neither `ip` nor `ips` |
| `400` | `Invalid: Missing ...` | A required field is missing |
| `400` | `Invalid: the request body must be a JSON object` | The body is not valid JSON, or is JSON but not an object (for example a list) |
| `400` | `Invalid: '<field>' must be a string of at most N characters` | A field is not a string or is too long. Limits: `ip` 45, `application` 64, `access_info` 2000, `username` and `password` 256 characters |
| `400` | `Invalid: 'ips' ...` | `ips` is not a list of strings, or has more than 1000 addresses |
| `400` | `Invalid: admin must be ...` | `admin` was something other than `0` or `1` |
| `401` | `Not authorized...` | Missing, wrong, or expired token, or the token's application does not match the `application` field |
| `401` | `Please use Bearer Token...` | The `Authorization` header is not in the form `Bearer <token>` |
| `413` | (HTML error page) | The request body is larger than 1 MB |

If your data is not showing up, see [Troubleshooting](setup.md#troubleshooting).

## Examples of POSTing data to PWNBoard

curl
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <ACCESS TOKEN GENERATED IN /manage_apps>" -d '{"ip": "10.1.1.254", "application": "Javalanche"}' https://pwnboard.win/pwn
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <ACCESS TOKEN GENERATED IN /manage_apps>" -d '{"ip": "10.1.1.254", "application": "ZeroPAM", "username": "admin", "password": "Change.me123!"}' https://pwnboard.win/creds
```

Bash (send a callback every minute)
```bash
while true; do
    curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <ACCESS TOKEN GENERATED IN /manage_apps>" -d '{"ip": "10.1.1.254", "application": "Javalanche"}' https://pwnboard.win/pwn
    sleep 60
done
```

Python
```py
# pip install requests
import requests

PWNBOARD_URL = "https://pwnboard.win"
HEADERS = {"Authorization": "Bearer <ACCESS TOKEN GENERATED IN /manage_apps>"}

callback_payload = {"ip": "10.1.1.254", "application": "Javalanche"}
resp = requests.post(f"{PWNBOARD_URL}/pwn", json=callback_payload, headers=HEADERS, timeout=10)
print(resp.status_code, resp.text.strip())

creds_payload = {"ip": "10.1.1.254", "application": "ZeroPAM", "username": "admin", "password": "Change.me123!"}
resp = requests.post(f"{PWNBOARD_URL}/creds", json=creds_payload, headers=HEADERS, timeout=10)
print(resp.status_code, resp.text.strip())
```

Go
```go
package main

import (
    "bytes"
    "fmt"
    "io"
    "net/http"
)

const (
    pwnboardURL = "https://pwnboard.win"
    token       = "<ACCESS TOKEN GENERATED IN /manage_apps>"
)

func post(path, body string) error {
    req, err := http.NewRequest("POST", pwnboardURL+path, bytes.NewBufferString(body))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    out, _ := io.ReadAll(resp.Body)
    fmt.Println(resp.StatusCode, string(bytes.TrimSpace(out)))
    return nil
}

func main() {
    if err := post("/pwn", `{"ip":"10.1.1.254","application":"Javalanche"}`); err != nil {
        fmt.Println("callback failed:", err)
    }
    if err := post("/creds", `{"ip":"10.1.1.254","application":"ZeroPAM","username":"admin","password":"Change.me123!"}`); err != nil {
        fmt.Println("creds failed:", err)
    }
}
```

PowerShell
```powershell
$PwnboardUrl = "https://pwnboard.win"
$Headers = @{ Authorization = "Bearer <ACCESS TOKEN GENERATED IN /manage_apps>" }

$callback = @{ ip = "10.1.1.254"; application = "Javalanche" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$PwnboardUrl/pwn" -Headers $Headers -ContentType "application/json" -Body $callback

$creds = @{ ip = "10.1.1.254"; application = "ZeroPAM"; username = "admin"; password = "Change.me123!" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$PwnboardUrl/creds" -Headers $Headers -ContentType "application/json" -Body $creds
```

C#
```csharp
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

class Program
{
    const string PwnboardUrl = "https://pwnboard.win";
    const string Token = "<ACCESS TOKEN GENERATED IN /manage_apps>";

    static async Task Main()
    {
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        var body = new StringContent("{\"ip\":\"10.1.1.254\",\"application\":\"Javalanche\"}", Encoding.UTF8, "application/json");
        var resp = await client.PostAsync($"{PwnboardUrl}/pwn", body);
        Console.WriteLine($"{(int)resp.StatusCode} {(await resp.Content.ReadAsStringAsync()).Trim()}");
    }
}
```

## Self-signed certificates
If PWNBoard is served on `localhost`, an IP address, or a private hostname, its HTTPS certificate is not signed by a public authority and your tool will refuse to connect. Either have your tool skip certificate validation, or trust Caddy's root certificate (see [Troubleshooting](setup.md#3-self-signed-certs-and-failed-post-requests)).

| Language | Skip certificate validation |
|----------|-----------------------------|
| curl | add `-k` |
| Python (requests) | pass `verify=False` to `requests.post` |
| Go | `http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}` (import `crypto/tls`) |
| PowerShell 7+ | add `-SkipCertificateCheck` to `Invoke-RestMethod` |
| Windows PowerShell 5.1 | run `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }` first |
| C# | `new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator })` |

Only do this against your own PWNBoard.
