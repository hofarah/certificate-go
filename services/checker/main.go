package main

import (
	"certificate/models/checker/arg"
	"certificate/models/checker/certificate"
	"fmt"
)

func main() {
	ok, filePath := arg.GetArg(arg.File)
	if !ok {
		fmt.Println("invalid param")
		return
	}
	cert, err := certificate.GetCertFromFile(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}
	certificate.PrintCert(cert)

	err = certificate.CheckExpireValidation(cert)
	if err != nil {
		fmt.Println(err)
		return
	}

}
