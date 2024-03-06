package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/term"
)

var ks *keystore.KeyStore
var keystorePath string

func initKeystore() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Unable to find home directory: %s\n", err)
		os.Exit(1)
	}
	ksPath := filepath.Join(home, ".ethereum/keystore")
	ks = keystore.NewKeyStore(ksPath, keystore.StandardScryptN, keystore.StandardScryptP)
	keystorePath = ksPath
}

func mainMenu() {
	options := []string{
		"Switch keystore path",
		"Generate account/key",
		"Import a private key into keystore",
		"Show address of a private key",
		"Show addresses in keystore",
		"Show a private key in keystore",
		"Exit",
	}

	for {
		fmt.Println("\nCommand Menu:")
		for i, option := range options {
			fmt.Printf("%d. %s\n", i+1, option)
		}

		choice := promptForChoice(len(options))
		if choice == -1 {
			continue
		}

		switch choice {
		case 1:
			if err := switchKeystore(); err != nil {
				fmt.Println("Error switching keystore:", err)
			}
		case 2:
			if _, err := generateAccount(); err != nil {
				fmt.Println("Error generating account:", err)
			}
		case 3:
			if _, err := importKey(); err != nil {
				fmt.Println("Error importing key:", err)
			}
		case 4:
			if err := showAddress(); err != nil {
				fmt.Println("Error showing address:", err)
			}
		case 5:
			if err := showAccounts(); err != nil {
				fmt.Println("Error showing accounts:", err)
			}
		case 6:
			if k, err := getPK(); err != nil {
				fmt.Println("Error getting private key:", err)
			} else {
				pkey := crypto.FromECDSA(k)
				fmt.Printf("Private Key: 0x%s\n", hexutil.Encode(pkey)[2:])
			}
		case 7:
			fmt.Println("Exiting...")
			return
		}

		promptForContinue()
	}
}

func promptForChoice(max int) int {
	fmt.Printf("Enter your choice (1-%d): ", max)
	var choice int
	if _, err := fmt.Scanf("%d\n", &choice); err != nil || choice < 1 || choice > max {
		fmt.Printf("Invalid choice. Please enter a number between 1 and %d.\n", max)
		return -1
	}
	return choice
}

func promptForContinue() {
	if _, err := readPrompt("Press any key to continue...", ""); err != nil {
		fmt.Println("Error reading prompt:", err)
	}
}

func readKey(path string) (common.Address, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return common.Address{}, nil, err
	}
	var a struct{ Address string }
	if err := json.Unmarshal(b, &a); err != nil {
		return common.Address{}, b, err
	}
	return common.HexToAddress(a.Address), b, nil
}

func readKeystoreKey(addr common.Address) ([]byte, error) {
	fileInfo, err := os.ReadDir(keystorePath)
	if err != nil {
		return nil, err
	}
	for _, f := range fileInfo {
		if f.IsDir() {
			continue
		}
		filePath := filepath.Join(keystorePath, f.Name())
		a, b, err := readKey(filePath)
		if err != nil {
			continue // Skip files that can't be read or don't match the address format
		}
		if a == addr {
			return b, nil
		}
	}
	return nil, fmt.Errorf("address %s not found", addr.Hex())
}

func decryptKey(key []byte) (*ecdsa.PrivateKey, error) {
	fmt.Printf(">>>Password: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	k, err := keystore.DecryptKey(key, string(passphrase))
	if err != nil {
		return nil, err
	}
	return k.PrivateKey, nil
}

func generateAccount() (string, error) {
	fmt.Printf(">Passphrase: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if len(passphrase) < 2 {
		fmt.Println("Input a passphrase (min=2)")
		return "", fmt.Errorf("passphrase too short")
	}

	account, err := ks.NewAccount(string(passphrase))
	if err != nil {
		return "", err // Return the error instead of using log.Fatal
	}

	addr := account.Address.Hex()
	fmt.Println("Address: " + addr)

	return addr, nil
}

func readPrompt(title string, prompt string) (string, error) {
	fmt.Println(title)
	// Create a new scanner for standard input
	scanner := bufio.NewScanner(os.Stdin)
	// Prompt the user for input
	fmt.Print(prompt)
	// Read the next line of input
	scanner.Scan()
	// Check for errors
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading input:", err)
		return "", err
	}

	// Get the entered string
	input := scanner.Text()

	// Print the entered string
	fmt.Println("You entered:", input)
	return input, nil
}

func importKey() (*accounts.Account, error) {
	fmt.Printf(">Enter a private key?: ")
	k, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	pkey := strings.TrimPrefix(string(k), "0x")

	fmt.Printf(">Enter a passphrase: ")
	k, err = term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	passphrase := string(k)

	privateKey, err := crypto.HexToECDSA(pkey)
	if err != nil {
		fmt.Println("Error converting private key:", err)
		return nil, err
	}

	account, err := ks.ImportECDSA(privateKey, passphrase)
	if err != nil {
		fmt.Println("Error importing a private key:", err)
		return nil, err
	}
	fmt.Println("address imported: ", account.Address.Hex())
	return &account, nil
}

func showAddress() error {
	fmt.Printf(">Enter a private key: ")
	k, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	pkey := strings.TrimPrefix(string(k), "0x")

	privateKey, err := crypto.HexToECDSA(pkey)
	if err != nil {
		fmt.Println("invalid private key")
		return err
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	fmt.Printf("address: %s \n", address)

	return nil
}

func getPK() (*ecdsa.PrivateKey, error) {
	addr, err := readPrompt("show the private key", "address: ")
	if err != nil {
		return nil, err
	}

	if !common.IsHexAddress(addr) {
		return nil, fmt.Errorf("invalid address")
	}

	b, err := readKeystoreKey(common.HexToAddress(addr))
	if err != nil {
		return nil, err
	}

	k, err := decryptKey(b)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func showAccounts() error {
	fileInfo, err := os.ReadDir(keystorePath)
	if err != nil {
		return err
	}
	fmt.Println("address(es) in keystore: " + keystorePath)
	fmt.Println("==================================================")
	for idx, f := range fileInfo {
		if f.IsDir() {
			continue
		}
		a, _, err := readKey(filepath.Join(keystorePath, f.Name()))
		if err == nil {
			fmt.Printf("%d: %s \n", idx+1, a.Hex()) // Ensure to use .Hex() for proper address formatting
		}
	}
	fmt.Println("==================================================")
	return nil
}

func switchKeystore() error {
	if path, err := readPrompt("input the keystore path", "path:"); err == nil {
		ks = keystore.NewKeyStore(path, keystore.StandardScryptN, keystore.StandardScryptP)
		keystorePath = path
		return nil
	} else {
		return err
	}
}

func main() {
	initKeystore()
	mainMenu()
}
