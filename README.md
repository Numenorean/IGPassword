# IGPassword
This lib provide you instagram password encryption (only ios/android auth)
### Installation
Install this package with command `go get -u github.com/Numenorean/IGPassword`

### Finding rsaKey
It is located in all instagram endpoints
ig-set-password-encryption-key-id: keyID
ig-set-password-encryption-pub-key: rsaKey

# Usage
```go
package main

import (
	"github.com/Numenorean/IGPassword"
	"fmt"
)

func main() {
    fmt.Println(igencryption.Encrypt("long key that starts from -----BEGIN PUBLIC KEY-----", "password", 136)) // keyID only as example
}
```
