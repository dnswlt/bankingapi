package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dnswlt/bankingapi/comdirect"
	"golang.org/x/term"
)

func readPassword(prompt string) string {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatalf("Error reading password from stdin: %v", err)
	}
	return string(password)
}

func readLine(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Error reading input from stdin: %v", err)
	}
	return strings.TrimSpace(input)
}

func printBalance(b *comdirect.AccountBalance) {
	a := b.GetAccount()
	iban := a.GetIban()
	balance := b.GetBalance()
	acctType := a.GetAccountType()
	name := acctType.GetText()
	fmt.Printf("%s %s %s\n", iban, name, balance.GetValue())
}

func printTransactions(txs []comdirect.AccountTransaction) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 4, 1, ' ', 0)
	for i := range txs {
		tx := &txs[i]
		amount := tx.GetAmount()
		bookingDate := tx.GetBookingDate()
		remittanceInfoList := tx.GetRemittanceInfoList()
		remittanceInfo := ""
		if len(remittanceInfoList) > 0 {
			remittanceInfo = remittanceInfoList[0]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t\n",
			tx.GetBookingStatus(),
			amount.GetUnit(),
			amount.GetValue(),
			bookingDate.GetDate(),
			remittanceInfo)
		for _, ri := range remittanceInfoList[1:] {
			fmt.Fprintf(w, "\t\t\t\t%s\t\n", ri)
		}
	}
	w.Flush()
}

func printPositions(positions []comdirect.DepotPosition) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 4, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(w, "WKN\tISIN\tQty\tPrice\tMkt Value\t\n")
	for i := range positions {
		p := &positions[i]

		wkn := p.GetWkn()
		instr := p.GetInstrument()
		isin := instr.GetIsin()
		qty := p.GetQuantity()
		curPrice := p.GetCurrentPrice()
		price := curPrice.GetPrice()
		mktValue := p.GetCurrentValue()

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t\n", wkn, isin, qty.GetValue(), price.GetValue(), mktValue.GetValue())
	}
	w.Flush()
}

func main() {
	credentialsPath := flag.String("credentials", ".bankingapi_credentials", "Path to JSON file with credentials")
	oAuthTokenPath := flag.String("oauth-token", ".bankingapi_oauth_token", "Path to JSON file with existing OAuth token")
	flag.Parse()

	var cred comdirect.Credentials

	if *credentialsPath != "" {
		var err error
		cred, err = comdirect.LoadCredentials(*credentialsPath)
		if err != nil {
			log.Fatalf("Failed to open credentials file: %v", err)
		}
		if cred.Password == "" {
			// Credentials file contains no password: retrieve interactively.
			cred.Password = readPassword("Enter your password/PIN: ")
		}
	} else {
		cred = comdirect.Credentials{
			ClientID:     readPassword("Enter your client_id: "),
			ClientSecret: readPassword("Enter your client_secret: "),
			Username:     readLine("Enter your username: "),
			Password:     readPassword("Enter your password/PIN: "),
		}
	}

	shouldRefreshToken := false
	oauthToken, err := comdirect.LoadOAuthToken(*oAuthTokenPath)
	if err != nil {
		log.Printf("Failed to read OAuth token from %s: %v", *oAuthTokenPath, err)
	} else {
		log.Printf("Successfully read existing OAuth token from %s", *oAuthTokenPath)
		tokenTTL := time.Until(oauthToken.ExpireTime)
		if tokenTTL < 10*time.Second {
			log.Printf("OAuth token expired at %v, will request a new token.", oauthToken.ExpireTime)
			oauthToken = nil
		} else if tokenTTL < 5*time.Minute {
			log.Printf("OAuth token will expire at %v, will refresh the token.", oauthToken.ExpireTime)
			shouldRefreshToken = true
		}
	}

	c := comdirect.NewClient(cred, oauthToken)
	log.Printf("Using client with session ID %s", c.SessionID())

	if oauthToken == nil {
		// No token yet.
		// Follow procedure from REST API documentation.

		// Step 2.1: fetch an OAuth token.
		err = c.FetchToken()
		if err != nil {
			log.Fatalf("Error fetching token: %v", err)
		}

		// Step 2.2 + 2.3: Get sessionTANInfo status.
		sessionTANInfo, err := c.RequestSessionTAN()
		if err != nil {
			log.Fatalf("Error fetching auth info: %v", err)
		}

		// Step 2.4 + 2.5: Activate TAN and retrieve OAuth token.
		fmt.Println("You should receive a TAN request via your configured mechanism (e.g. photoTAN).")
		tan := readLine("Enter TAN (leave empty if you confirmed via photoTAN): ")
		err = c.ActivateSessionTAN(tan, sessionTANInfo)
		if err != nil {
			log.Fatalf("Error activating session TAN: %v", err)
		}

		// Save token for later use
		if *oAuthTokenPath != "" {
			comdirect.SaveOAuthToken(*oAuthTokenPath, c.OAuthToken())
		}
	}
	if shouldRefreshToken {
		err := c.RefreshToken()
		if err != nil {
			log.Fatalf("Failed to refresh token: %v", err)
		}
		if *oAuthTokenPath != "" {
			err := comdirect.SaveOAuthToken(*oAuthTokenPath, c.OAuthToken())
			if err != nil {
				log.Fatalf("Failed to save refreshed token: %v", err)
			}
		}
	}

	// Client is ready for use.

	balances, err := c.ListAccountBalances()
	if err != nil {
		log.Fatalf("Error listing balances: %v", err)
	}
	for i := range balances {
		printBalance(&balances[i])
		txs, err := c.ListAccountTransactions(balances[i].GetAccountId())
		if err != nil {
			log.Printf("Error listing transactions: %v", err)
			continue
		}
		printTransactions(txs)
		fmt.Println()
	}

	depots, err := c.ListDepots()
	if err != nil {
		log.Fatalf("Error listing depots: %v", err)
	}

	for _, depot := range depots {
		fmt.Printf("Positions for depot %s (%s).\n", depot.GetDepotDisplayId(), depot.GetDepotId())
		positions, err := c.GetDepotPositions(depot.GetDepotId())
		if err != nil {
			log.Printf("Failed to get depot positions: %v", err)
			continue
		}
		printPositions(positions)
	}

	if *oAuthTokenPath == "" {
		// If we don't save the token, there is no point in keeping it alive.
		err = c.RevokeToken()
		if err != nil {
			log.Fatalf("Error revoking token: %v", err)
		}
	}
}
