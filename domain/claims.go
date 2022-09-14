package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// HMAC_Sample_Secret is used in authToken.go
const HMAC_Sample_Secret = "hmacSampleSecret"

// ACCESS_TOKEN_DURATION is used in login.go
const ACCESS_TOKEN_DURATION = time.Hour

type AccessTokenClaims struct {
	Customer_ID string   `json:"customer_id"`
	Accounts    []string `json:"accounts"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	jwt.StandardClaims
}

// IsUserRole() returns true if the AccessTokenClaims role field equals "user", false otherwise
func (c AccessTokenClaims) IsUserRole() bool {
	return c.Role == "user"
}

// IsValidCustomerID() returns true if the AccessTokenClaims Customer_ID field matches the customer ID provided, false otherwise
func (c AccessTokenClaims) IsValidCustomerID(customer_id string) bool {
	return c.Customer_ID == customer_id
}

// IsValidAccountID() returns true if the account_id is blank (as is the case for the admin account) or, if not blank,
// it ranges over the account IDs listed in the AccessTokenClaims Accounts field, returning true if there is a match
// and false otherwise
func (c AccessTokenClaims) IsValidAccountID(account_id string) bool {
	// in the event of the admin account, the account ID will be empty but IsValidAccountID should still return true
	if account_id != "" {
		// initialize acctFound to false
		acctFound := false
		for _, acctID := range c.Accounts {
			if acctID == account_id {
				// update acctFound to true
				acctFound = true
				// break out of the for loop
				break
			}
		}
		return acctFound
	}
	return true
}

// IsRequestVerifiedWithTokenClaims() returns false if the AccessTokenClaims customer ID field does not match the customer ID
// provided in the request or if the AccessTokenClaims accounts field doesn't contain the account_id provided in the request,
// otherwise it returns true
func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParameters map[string]string) bool {
	if !c.IsValidCustomerID(urlParameters["customer_id"]) {
		return false
	}
	if !c.IsValidAccountID(urlParameters["account_id"]) {
		return false
	}
	return true
}
