package main

import (
	"encoding/json"
	"fmt"
	"log"

	_ "embed"
)

//go:embed subdomainFinger.json
var subdomainFinger string

type FingerprintRecord struct {
	CICDPass      bool
	Cname         []string
	Discussion    string
	Documentation string
	Fingerprint   string
	HTTPStatus    interface{}
	NXDomain      bool
	Service       string
	Status        string
	Vulnerable    bool
}

type PackjsonSubdomain struct {
	Fingerprint []FingerprintRecord
}

func main() {

	// 使用零长度切片，让json.Unmarshal自动调整大小
	items := make([]FingerprintRecord, 0)
	err := json.Unmarshal([]byte(subdomainFinger), &items)
	if err != nil {
		log.Fatal(err)
	}

	// 打印解析后的数据
	for _, item := range items {
		fmt.Printf("Cname: %v\n", item.Cname)
		fmt.Printf("Service: %s\n", item.Service)
		fmt.Printf("Vulnerable: %t\n", item.Vulnerable)
		fmt.Println("-------------")
	}
}
