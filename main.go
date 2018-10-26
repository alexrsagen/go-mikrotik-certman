package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/jlaffaye/ftp"

	"gopkg.in/routeros.v2"
)

type config struct {
	Router struct {
		APIAddr, FTPAddr   string
		Username, Password string

		PreScripts, PostScripts []string
	}
	Cert struct {
		Name       string
		Passphrase string

		LocalCertPath, LocalKeyPath   string
		RemoteCertPath, RemoteKeyPath string
	}
}

type router struct {
	ftp *ftp.ServerConn
	api *routeros.Client
}

func main() {
	c, r := new(config), new(router)

	configPath := flag.String("c", "config.json", "Configuration file")
	flag.Parse()

	fmt.Printf("reading config... ")
	configBuf, err := ioutil.ReadFile(*configPath)
	if err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	if err = json.Unmarshal(configBuf, &c); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	fmt.Println("done.")

	fmt.Printf("opening cert file... ")
	fileCert, err := os.Open(c.Cert.LocalCertPath)
	if os.IsNotExist(err) {
		fmt.Printf("fail: %v\n", err)
		return
	}
	defer fileCert.Close()
	fmt.Println("done.")

	fmt.Printf("opening key file... ")
	fileKey, err := os.Open(c.Cert.LocalKeyPath)
	if os.IsNotExist(err) {
		fmt.Printf("fail: %v\n", err)
		return
	}
	defer fileKey.Close()
	fmt.Println("done.")

	fmt.Printf("getting cert fingerprint... ")
	certBytes, err := ioutil.ReadAll(fileCert)
	if err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	if _, err = fileCert.Seek(0, 0); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	certBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	certSHA := sha256.Sum256(cert.Raw)
	certFingerprint := hex.EncodeToString(certSHA[:])
	fmt.Println("done.")

	fmt.Printf("connecting to router ftp... ")
	if r.ftp, err = ftp.Dial(c.Router.FTPAddr); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	if err = r.ftp.Login(c.Router.Username, c.Router.Password); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	fmt.Println("done.")

	fmt.Printf("uploading files to router... ")
	if err = r.ftp.Stor(c.Cert.RemoteCertPath, fileCert); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	if err = r.ftp.Stor(c.Cert.RemoteKeyPath, fileKey); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	if err = r.ftp.Logout(); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	fmt.Println("done.")

	fmt.Printf("wait for router to flush files to flash... ")
	time.Sleep(time.Second)
	fmt.Println("done.")

	fmt.Printf("connecting to router api... ")
	if r.api, err = routeros.Dial(c.Router.APIAddr, c.Router.Username, c.Router.Password); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	defer r.api.Close()
	fmt.Println("done.")

	if len(c.Router.PreScripts) > 0 {
		fmt.Printf("running pre-import scripts... ")
		for _, scriptName := range c.Router.PreScripts {
			reply, err := r.api.Run("/system/script/print", "?name="+scriptName)
			if err != nil {
				fmt.Printf("fail: %v\n", err)
				return
			}
			if len(reply.Re) == 0 {
				fmt.Printf("fail: could not find script \"%s\" on router\n", scriptName)
				return
			}
			if _, err := r.api.Run("/system/script/run", "=.id="+reply.Re[0].Map[".id"]); err != nil {
				fmt.Printf("fail: %v\n", err)
				return
			}
		}
		fmt.Println("done.")
	}

	fmt.Printf("importing keypair on router... ")

	// Remove any existing keypair with same certificate fingerprint
	reply, err := r.api.Run("/certificate/print", "?fingerprint="+certFingerprint)
	if err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	if len(reply.Re) > 0 {
		if _, err = r.api.Run("/certificate/remove", "=.id="+reply.Re[0].Map[".id"]); err != nil {
			fmt.Printf("fail: %v\n", err)
			return
		}
	}

	// Import new keypair
	if _, err = r.api.Run("/certificate/import", "=file-name="+c.Cert.RemoteCertPath, "=passphrase="+c.Cert.Passphrase); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	if _, err = r.api.Run("/certificate/import", "=file-name="+c.Cert.RemoteKeyPath, "=passphrase="+c.Cert.Passphrase); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}

	// Find newly imported keypair ID
	reply, err = r.api.Run("/certificate/print", "?fingerprint="+certFingerprint)
	if err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}
	if len(reply.Re) == 0 {
		fmt.Println("fail: could not find imported keypair")
		return
	}

	// Update keypair name
	if _, err = r.api.Run("/certificate/set", "=.id="+reply.Re[0].Map[".id"], "=name="+c.Cert.Name); err != nil {
		fmt.Printf("fail: %v\n", err)
		return
	}

	fmt.Println("done.")

	if len(c.Router.PostScripts) > 0 {
		fmt.Printf("running post-import scripts... ")
		for _, scriptName := range c.Router.PostScripts {
			reply, err := r.api.Run("/system/script/print", "?name="+scriptName)
			if err != nil {
				fmt.Printf("fail: %v\n", err)
				return
			}
			if len(reply.Re) == 0 {
				fmt.Printf("fail: could not find script \"%s\" on router\n", scriptName)
				return
			}
			if _, err := r.api.Run("/system/script/run", "=.id="+reply.Re[0].Map[".id"]); err != nil {
				fmt.Printf("fail: %v\n", err)
				return
			}
		}
		fmt.Println("done.")
	}
}
