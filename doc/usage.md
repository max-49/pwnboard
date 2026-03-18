**PWNBOARD URL AND DOCUMENTATION**
Replace pwnboard.win with your PWNBoard URL

To create an access token for your application:
1. Ask the admin to make a PWNBoard account for you
2. Go to Settings --> Manage Apps (/manage_apps) --> Add Token
3. Ensure the Application is the same name you are putting in the Application field (not case sensitive)
4. Copy and save the created token (you will not be able to see it again)

HOW TO SEND YOUR *CALLBACKS* (C2 callbacks):
POST data in this format to https://www.pwnboard.win/pwn :
*Minimum Required Parameters*
`{"ip": "<ip>", "application": "<your tool>"}`

*Optional Parameters*
`{"ip": "<ip>", "application": "<your tool>", "access_type": "<type/method of access>", "access_info": "<optional information to access this tool (URL, creds, etc.)>" }`

HOW TO SEND YOUR *CREDENTIALS* (send valid credentials to PWNBoard!)
POST data in this format to https://www.pwnboard.win/creds :
*Minimum Required Parameters*
`{"ip": "<ip>", "username": "<username>", "password": "<password>"}`

*Optional Parameters*
`{"ip": "<ip>", "username": "<username>", "password": "<password>", "admin": <0 or 1>}`

Examples of POSTing data to PWNBoard:

Curl
```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <ACCESS TOKEN GENERATED IN /manage_apps>" -d '{"ip": "10.1.1.254", "application": "Javalanche", "access_type": "https c2"}' https://www.pwnboard.win/pwn
```

Python
```py
# pip install requests
import requests

url = "https://www.pwnboard.win/pwn"
payload = {"ip": "10.1.1.254", "application": "Javalanche", "access_type": "https c2"}
resp = requests.post(url, json=payload, headers={"Content-Type": "application/json", "Authorization": "Bearer <ACCESS TOKEN GENERATED IN /manage_apps>"})

assert resp.text.strip() == "valid"
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
    req.Header.Set("Authorization", "Bearer <ACCESS TOKEN GENERATED IN /manage_apps>")
    client := &http.Client{}
    resp, err := client.Do(req)
    defer resp.Body.Close()
}
```