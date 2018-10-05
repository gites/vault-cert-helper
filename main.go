package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	vaultApi "github.com/hashicorp/vault/api"
	flags "github.com/jessevdk/go-flags"
	minio "github.com/minio/minio-go"
	"github.com/spf13/viper"
)

var opts struct {
	Verbose []bool `short:"v" long:"verbose" description:"Show verbose debug information"`
	Version []bool `short:"V" long:"version" description:"Show version information"`
}
var (
	// Name of the program
	Name string
	// GitCommit hash
	GitCommit string
	// Version build
	Version string
	//HumanVersion easy readable for Humans
	HumanVersion = fmt.Sprintf("%s %s (%s)", Name, Version, GitCommit)
)

func main() {

	flags.Parse(&opts)

	if len(opts.Version) > 0 {
		fmt.Println(HumanVersion)
		return
	}
	// Set config file name and look for it in few directories
	viper.SetConfigName("vault-cert-helper")
	viper.AddConfigPath("$HOME")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/config")
	// Set env var prefix and auto read envs
	viper.SetEnvPrefix("VCH")
	viper.AutomaticEnv()
	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalln("Error reading config file: ", err)
	}
	// Get vaules from config file
	authMethod := viper.GetString("authMethod")
	token := viper.GetString("token")
	vaultURL := viper.GetString("vault")
	ttlDefault := viper.GetString("ttl")
	pkiPathDefault := viper.GetString("pkiPath")
	s3SecretPath := viper.GetString("s3SecretPath")
	insecure := viper.GetBool("insecure")
	caCert := viper.GetString("caCert")
	caPath := viper.GetString("caPath")
	pkiSpec := viper.GetStringMapString("pkiSpec")

	// Create Vault config object and apply vault env variables
	config := vaultApi.DefaultConfig()
	config.ReadEnvironment()

	// If we need custom TLS configuration, then set it
	if insecure == true || caCert != "" || caPath != "" {
		tls := &vaultApi.TLSConfig{
			CACert:   caCert,
			CAPath:   caPath,
			Insecure: insecure,
		}
		config.ConfigureTLS(tls)
	}
	// Set Vault address from config file
	if vaultURL != "" {
		config.Address = vaultURL
	}

	// Create Vault cient and get needed secrets
	vault, err := vaultApi.NewClient(config)
	if err != nil {
		log.Fatalln("Failed to create Vault client: ", err)
		return
	}
	// Set Vault token depending on auth method
	if authMethod == "token" {
		if token != "" {
			vault.SetToken(viper.GetString("token"))
		}
	} else if authMethod == "sa" {
		authPath := viper.GetString("authPath")
		authRole := viper.GetString("authRole")

		saToken, err := ioutil.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			log.Fatalln("Error reading serviceaccount token: ", err)
		}
		authReq := map[string]interface{}{
			"role": authRole,
			"jwt":  string(saToken),
		}
		authResp, err := vault.Logical().Write(authPath, authReq)
		if err != nil {
			log.Fatalln("Error loging to Vault: ", err)
		}
		vault.SetToken(authResp.Auth.ClientToken)
	} else {
		log.Fatalln("Unknow auth method: ", authMethod)
		return
	}

	// Only v1 Vault KV backend is supported
	secretValues, err := vault.Logical().Read(s3SecretPath)
	if err != nil {
		log.Fatalln("Can't read secretes from Vault: ", err)
		return
	}

	accessKeyID := fmt.Sprint(secretValues.Data["accessKeyID"])
	secretAccessKey := fmt.Sprint(secretValues.Data["secretAccessKey"])

	if accessKeyID == "" || secretAccessKey == "" {
		log.Fatalln("Invalid S3 credentials")
	}

	// Initialize Minio client object
	endpoint := viper.GetString("endpoint")

	u, err := url.Parse(endpoint)
	if err != nil {
		log.Fatalln("Bad endpoint:", err)
	}
	useSSL := false
	if u.Scheme == "https" {
		useSSL = true
	}

	minioClient, err := minio.New(u.Host, accessKeyID, secretAccessKey, useSSL)
	if err != nil {
		log.Fatalln("Mino client: ", err)
	}

	for pki := range pkiSpec {
		spec := viper.GetStringMapString("pkiSpec." + pki)

		if spec["ttl"] == "" {
			spec["ttl"] = ttlDefault
		}
		if spec["pkiPath"] == "" {
			spec["pkiPath"] = pkiPathDefault
		}
		// Check if cert is still valid
		certObject, err := url.Parse(spec["cert"])
		if err != nil {
			log.Fatalln("Bad Cert URL: ", err)
		}

		generate := checkCert(certObject, minioClient)
		if !generate {
			continue
		}
		// Sned CSR to Vault
		csrObject, err := url.Parse(spec["csr"])
		if err != nil {
			log.Fatalln("Bad CSR URL: ", err)
		}
		csr := string(getCsr(csrObject, minioClient))

		csrReq := map[string]interface{}{
			"csr": csr,
			"ttl": spec["ttl"],
		}
		cert, err := vault.Logical().Write(spec["pkiPath"], csrReq)
		if err != nil {
			log.Fatalln("Failed to sing certificate: ", err)
			return
		}
		// Upload signed cert to bucket
		cert2 := fmt.Sprint(cert.Data["certificate"])
		_, err = minioClient.PutObject(certObject.Host, certObject.Path[1:], strings.NewReader(cert2), -1, minio.PutObjectOptions{ContentType: "application/x-x509-ca-cert"})
		if err != nil {
			log.Fatalln(err)
			return
		}
	}

}
func checkCert(certObject *url.URL, minioClient *minio.Client) bool {
	// Verifies if cert is still valid. If cert is after half of valid time it is marked as invalid.
	certBuf, _ := getFromS3(certObject, minioClient)

	if len(certBuf) == 0 {
		log.Println("Missing cert", certObject, "generating new one.")
		return true
	}

	// check if cert is valid
	p, _ := pem.Decode(certBuf)
	parsedCert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		log.Fatalln(certObject, err)
	}
	validFor := parsedCert.NotAfter.Sub(parsedCert.NotBefore)
	since := time.Since(parsedCert.NotBefore)
	if validFor/2 < since {
		log.Println("Cert CN:", parsedCert.DNSNames[0], certObject, "after half of valid time (", since, "old), generating new one.")
		return true
	}
	printLogs("Cert CN: " + parsedCert.DNSNames[0] + " " + certObject.Host + certObject.Path + " still valid.")
	return false
}
func getCsr(csrObject *url.URL, minioClient *minio.Client) []byte {
	// Gets csr fromls s3 bucket
	csrBuf, err := getFromS3(csrObject, minioClient)
	if len(csrBuf) == 0 {
		log.Fatalln("Missing CSR file:", csrObject, err)
	}
	return csrBuf
}

func getFromS3(obj *url.URL, client *minio.Client) ([]byte, error) {
	// Gets an object from s3 bucket
	var data []byte

	// Check if we can connect
	stat, err := client.StatObject(obj.Host, obj.Path[1:], minio.StatObjectOptions{})
	re := regexp.MustCompile("^Get ")
	if re.FindString(fmt.Sprint(err)) == "Get " {
		log.Fatalln(err)
	}
	// Read obj
	if stat.Size != 0 {
		object, err := client.GetObject(obj.Host, obj.Path[1:], minio.GetObjectOptions{})
		if err != nil {
			log.Fatalln(err)
		}
		data = make([]byte, stat.Size)
		size, err := object.Read(data)
		if size == 0 && err != nil {
			log.Fatalln(err)
		}
	}
	return data, err
}

func printLogs(msg string) {
	// Prints messages in -v flag is passed to cmd
	if len(opts.Verbose) > 0 {
		log.Println(msg)
	}
}
