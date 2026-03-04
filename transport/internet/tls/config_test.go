package tls_test

import (
	"bytes"
	gotls "crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

func TestCertificateIssuing(t *testing.T) {
	ct, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	certificate := ParseCertificate(ct)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	tlsConfig := c.GetTLSConfig()
	xrayCert, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
		ServerName: "www.example.com",
	})
	common.Must(err)

	x509Cert, err := x509.ParseCertificate(xrayCert.Certificate[0])
	common.Must(err)
	if !x509Cert.NotAfter.After(time.Now()) {
		t.Error("NotAfter: ", x509Cert.NotAfter)
	}
}

func TestExpiredCertificate(t *testing.T) {
	caCert, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	expiredCert, _ := cert.MustGenerate(caCert, cert.NotAfter(time.Now().Add(time.Minute*-2)), cert.CommonName("www.example.com"), cert.DNSNames("www.example.com"))

	certificate := ParseCertificate(caCert)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	certificate2 := ParseCertificate(expiredCert)

	c := &Config{
		Certificate: []*Certificate{
			certificate,
			certificate2,
		},
	}

	tlsConfig := c.GetTLSConfig()
	xrayCert, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
		ServerName: "www.example.com",
	})
	common.Must(err)

	x509Cert, err := x509.ParseCertificate(xrayCert.Certificate[0])
	common.Must(err)
	if !x509Cert.NotAfter.After(time.Now()) {
		t.Error("NotAfter: ", x509Cert.NotAfter)
	}
}

func TestInsecureCertificates(t *testing.T) {
	c := &Config{}

	tlsConfig := c.GetTLSConfig()
	if len(tlsConfig.CipherSuites) > 0 {
		t.Fatal("Unexpected tls cipher suites list: ", tlsConfig.CipherSuites)
	}
}

func TestBuildCertificatesDoesNotMutateInlineKey(t *testing.T) {
	StopAllOcspTickers()
	t.Cleanup(StopAllOcspTickers)

	ct, _ := cert.MustGenerate(nil, cert.CommonName("www.example.com"), cert.DNSNames("www.example.com"))
	certificate := ParseCertificate(ct)
	certificate.Usage = Certificate_ENCIPHERMENT

	originalKey := append([]byte(nil), certificate.Key...)
	if len(originalKey) == 0 {
		t.Fatal("generated key PEM should not be empty")
	}

	cfg := &Config{
		Certificate: []*Certificate{certificate},
	}

	first := cfg.BuildCertificates()
	if len(first) != 1 {
		t.Fatalf("first BuildCertificates len=%d, want 1", len(first))
	}
	if first[0].Load() == nil {
		t.Fatal("first BuildCertificates returned nil certificate pointer")
	}

	second := cfg.BuildCertificates()
	if len(second) != 1 {
		t.Fatalf("second BuildCertificates len=%d, want 1", len(second))
	}
	if second[0].Load() == nil {
		t.Fatal("second BuildCertificates returned nil certificate pointer")
	}

	if !bytes.Equal(certificate.Key, originalKey) {
		t.Fatal("BuildCertificates mutated source key bytes")
	}
}

func TestGetTLSConfigRemainsUsableAcrossRepeatedBuilds(t *testing.T) {
	StopAllOcspTickers()
	t.Cleanup(StopAllOcspTickers)

	ct, _ := cert.MustGenerate(nil, cert.CommonName("www.example.com"), cert.DNSNames("www.example.com"))
	certificate := ParseCertificate(ct)
	certificate.Usage = Certificate_ENCIPHERMENT

	cfg := &Config{
		Certificate: []*Certificate{certificate},
	}

	hello := &gotls.ClientHelloInfo{ServerName: "www.example.com"}

	firstTLSConfig := cfg.GetTLSConfig()
	firstCert, err := firstTLSConfig.GetCertificate(hello)
	common.Must(err)
	if firstCert == nil {
		t.Fatal("first GetTLSConfig returned nil certificate")
	}

	secondTLSConfig := cfg.GetTLSConfig()
	secondCert, err := secondTLSConfig.GetCertificate(hello)
	common.Must(err)
	if secondCert == nil {
		t.Fatal("second GetTLSConfig returned nil certificate")
	}
}

func BenchmarkCertificateIssuing(b *testing.B) {
	ct, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	certificate := ParseCertificate(ct)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	tlsConfig := c.GetTLSConfig()
	lenCerts := len(tlsConfig.Certificates)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
			ServerName: "www.example.com",
		})
		delete(tlsConfig.NameToCertificate, "www.example.com")
		tlsConfig.Certificates = tlsConfig.Certificates[:lenCerts]
	}
}
