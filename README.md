# dotnethash

A go package to generate and verify .NET Core password hash

```
package main

import (
  "fmt"
  hash "github.com/dotnethash/dotnethash"
)

func main() {
  hasher := hash.NewHasher()

	password := "P@ssw0rd"
	hashedPassword, err := hasher.HashPassword(password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	isPasswordValid := hasher.VerifyPassword(hashedPassword, password)

	fmt.Println("Hashed Password:", hashedPassword)
	fmt.Println("Is Password Valid:", isPasswordValid)
}
```