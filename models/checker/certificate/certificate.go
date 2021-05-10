package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func GetCertFromFile(path string) (x509.Certificate, error) {

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return x509.Certificate{}, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return x509.Certificate{}, errors.New("failed to decode pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return x509.Certificate{}, err
	}
	return *cert, nil
}

func PrintCert(certificate x509.Certificate) {
	fmt.Println("Raw: ", certificate.Raw, "\n",
		"RawTBSCertificate:", certificate.RawTBSCertificate, "\n",
		"RawSubjectPublicKeyInfo:", certificate.RawSubjectPublicKeyInfo, "\n",
		"RawSubject:", certificate.RawSubject, "\n",
		"RawIssuer:", certificate.RawIssuer, "\n",
		"Signature:", certificate.Signature, "\n",
		"SignatureAlgorithm:", certificate.SignatureAlgorithm, "\n",
		"PublicKeyAlgorithm:", certificate.PublicKeyAlgorithm, "\n",
		"PublicKey:", certificate.PublicKey, "\n",
		"Version:", certificate.Version, "\n",
		"SerialNumber:", certificate.SerialNumber, "\n",
		"Issuer:", certificate.Issuer, "\n",
		"Subject:", certificate.Subject, "\n",
		"NotBefore:", certificate.NotBefore, "\n",
		"NotAfter:", certificate.NotAfter, "\n",
		"KeyUsage:", certificate.KeyUsage, "\n",
		"Extensions:", certificate.Extensions, "\n",
		"ExtraExtensions:", certificate.ExtraExtensions, "\n",
		"UnhandledCriticalExtensions:", certificate.UnhandledCriticalExtensions, "\n",
		"ExtKeyUsage:", certificate.ExtKeyUsage, "\n",
		"UnknownExtKeyUsage:", certificate.UnknownExtKeyUsage, "\n",
		"BasicConstraintsValid:", certificate.BasicConstraintsValid, "\n",
		"IsCA:", certificate.IsCA, "\n",
		"MaxPathLen:", certificate.MaxPathLen, "\n",
		"MaxPathLenZero:", certificate.MaxPathLenZero, "\n",
		"SubjectKeyId:", certificate.SubjectKeyId, "\n",
		"AuthorityKeyId:", certificate.AuthorityKeyId, "\n",
		"OCSPServer:", certificate.OCSPServer, "\n",
		"IssuingCertificateURL:", certificate.IssuingCertificateURL, "\n",
		"DNSNames:", certificate.DNSNames, "\n",
		"EmailAddresses:", certificate.EmailAddresses, "\n",
		"IPAddresses:", certificate.IPAddresses, "\n",
		"URIs:", certificate.URIs, "\n",
		"PermittedDNSDomainsCritical:", certificate.PermittedDNSDomainsCritical, "\n",
		"PermittedDNSDomains:", certificate.PermittedDNSDomains, "\n",
		"ExcludedDNSDomains:", certificate.ExcludedDNSDomains, "\n",
		"PermittedIPRanges:", certificate.PermittedIPRanges, "\n",
		"ExcludedIPRanges:", certificate.ExcludedIPRanges, "\n",
		"PermittedEmailAddresses:", certificate.PermittedEmailAddresses, "\n",
		"ExcludedEmailAddresses:", certificate.ExcludedEmailAddresses, "\n",
		"PermittedURIDomains:", certificate.PermittedURIDomains, "\n",
		"ExcludedURIDomains:", certificate.ExcludedURIDomains, "\n",
		"CRLDistributionPoints:", certificate.CRLDistributionPoints, "\n",
		"PolicyIdentifiers:", certificate.PolicyIdentifiers)
}
func CheckTimeValidate(certificate x509.Certificate) error {
	if certificate.NotBefore.IsZero() {
		return errors.New("expired cert: code 13")
	}
	if certificate.NotAfter.IsZero() {
		return errors.New("expired cert: code 14")
	}
	return nil
}
