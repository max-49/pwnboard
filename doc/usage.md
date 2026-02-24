**PWNBOARD URL AND DOCUMENTATION**
PWNboard URL: https://www.pwnboard.win/

HOW TO SEND YOUR *CALLBACKS* (C2 callbacks):
POST data in this format to https://www.pwnboard.win/pwn :
*Minimum Required Parameters*
`{"ip": "<ip>", "application": "<your tool>"}`

*Optional Parameters*
`{"ip": "<ip>", "application": "<your tool>", "access_type": "<type/method of access>"}`

HOW TO SEND YOUR *CREDENTIALS* (send valid credentials to pwnboard!)
POST data in this format to https://www.pwnboard.win/creds :
*Minimum Required Parameters*
`{"ip": "<ip>", "username": "<username>", "password": "<password>"}`

*Optional Parameters*
`{"ip": "<ip>", "username": "<username>", "password": "<password>", "admin": <0 or 1>}`

Examples of POSTing data to pwnboard:

Curl
```bash
curl -X POST -H "Content-Type: application/json" -d '{"ip": "10.1.1.254", "application": "Javalanche", "access_type": "https c2"}' https://www.pwnboard.win/pwn
```

Python
```py
# pip install requests
import requests

url = "https://www.pwnboard.win/pwn"
payload = {"ip": "10.1.1.254", "application": "Javalanche", "access_type": "https c2"}
resp = requests.post(url, json=payload, headers={"Content-Type": "application/json"})

assert resp.text.strip() == "valid"
```

PowerShell
```ps
$uri = "https://www.pwnboard.win/pwn"
$body = '{"ip":"10.1.1.254","application":"Javalanche","access_type":"https c2"}'

$response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json'
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

func main() {
    url := "https://www.pwnboard.win/pwn"
    jsonStr := []byte(`{"ip":"10.1.1.254","application":"Javalanche","access_type":"https c2"}`)
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
    req.Header.Set("Content-Type", "application/json")
    client := &http.Client{}
    resp, err := client.Do(req)
    defer resp.Body.Close()
}
```

NEW ADDITION AS OF PWNBOARD v2.0.0!!!!

Everything above still applies, except you need an extra header (Authorization) to POST data.

To get an Access Key:
1. Ask the admin to make a pwnboard account for you
2. Go to Settings --> Manage Apps --> Add Token
3. Ensure the Application is the same name you are putting in the Application field
4. Copy and save the created token (you will not be able to see it again)

When POSTing data:
Add an extra HTTP Header "Authorization" with the value "Bearer <access token>"

ex. 

Curl
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer d4h80fh08dh80aa1222" -d '{"ip": "10.1.1.254", "application": "Javalanche", "access_type": "https c2"}' https://www.pwnboard.win/pwn
```

Python
```py
# pip install requests
import os
import requests

PWNBOARD_ACCESS = os.environ.get("PWNBOARD_ACCESS", None)
url = "https://www.pwnboard.win/pwn"
payload = {"ip": "10.1.1.254", "application": "Javalanche", "access_type": "https c2"}
resp = requests.post(url, json=payload, headers={"Content-Type": "application/json", "Authorization": f"Bearer {PWNBOARD_ACCESS}"})

assert resp.text.strip() == "valid"
```