package service

import (
	"github.com/gtaylor314/Banking-Auth/domain"
	"github.com/gtaylor314/Banking-Auth/dto"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gtaylor314/Banking-Lib/errs"
	"github.com/gtaylor314/Banking-Lib/logger"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
}

type DefaultAuthService struct {
	repo     domain.AuthRepository
	rolePerm domain.RolePermissions
}

// Login() takes a login request, finds the customer id, account ids associated with the customer id, and the role of the
// individual and generates the proper claims, authToken, and accessToken
func (d DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	// creating two pointers - one to a login object and one to the custom error handler object (AppError)
	var login *domain.Login
	var appErr *errs.AppError

	// FindBy() populates our login object with customer id, all account ids (separated by a comma) belonging to the customer id
	// and the individual's role based on the username and password provided in the login request
	login, appErr = d.repo.FindBy(req.Username, req.Password)
	if appErr != nil {
		return nil, appErr
	}

	// ClaimsForAccessTokens uses the login object to determine if the login is for a user or an administrator - it returns
	// the relevant claims
	claims := login.ClaimsForAccessTokens()
	// NewAuthToken uses the claims generated above to create an authToken
	authToken := domain.NewAuthToken(claims)
	// NewAccessToken() signs the authToken and returns a complete JWT token (accessToken as we call it)
	accessToken, appErr := authToken.NewAccessToken()
	if appErr != nil {
		return nil, appErr
	}
	return &dto.LoginResponse{AccessToken: accessToken}, nil
}

// Verify() takes the urlParams and verifies them against the JWT token
func (d DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError {
	// jwtTokenFromString() takes our access token string and parses it into a JWT token object
	jwtToken, err := jwtTokenFromString(urlParams["token"])
	if err != nil {
		return errs.UnexpectedErr(err.Error())
	}

	if jwtToken.Valid {
		// type cast the claims field in jwtToken to the type pointer to AccessTokenClaims
		claims := jwtToken.Claims.(*domain.AccessTokenClaims)
		// check if the claims are for the user role
		if claims.IsUserRole() {
			// if the claims are for the user role, verify them against the request
			if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
				return errs.UnexpectedErr("unexpected error verifying request against token claims")
			}
		}
		// confirm that the role listed in the token claims has permission to use the route specified
		if !d.rolePerm.IsAuthorizedFor(claims.Role, urlParams["routeName"]) {
			return errs.AuthorizationErr("not authorized")
		}
		return nil
	}
	// if the jwtToken is invalid
	return errs.AuthorizationErr("invalid token")
}

// jwtTokenFromString() takes the string form of our access token and parses it into a jwt.Token (struct) and returns the
// token object
func jwtTokenFromString(accessToken string) (*jwt.Token, error) {
	// ParseWithClaims() parses the token but does not verify the signature
	token, err := jwt.ParseWithClaims(accessToken, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_Sample_Secret), nil
	})
	if err != nil {
		logger.Error("error parsing access token " + err.Error())
		return nil, err
	}
	return token, nil
}

// NewLoginService() initializes a new DefaultAuthService with a repository and role permissions
func NewLoginService(repo domain.AuthRepository, rolePerm domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo: repo, rolePerm: rolePerm}
}
