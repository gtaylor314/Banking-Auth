package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gtaylor314/Banking-Auth/domain"
	"github.com/gtaylor314/Banking-Auth/service"

	"github.com/gtaylor314/Banking-Lib/logger"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)

func Start() {
	// check if all environment variables are defined
	err := envVariablesCheck()
	// if the error is not nil, one of the environment variables is missing and the application will exit
	if err != nil {
		return
	}

	// create new mux
	router := mux.NewRouter()

	// create authorization repository using NewAuthRepository func - uses getDbClient func to pass in a db connection
	authRepo := domain.NewAuthRepository(getDbClient())

	// create authHandler using newly created authRepo and the GetRolePermissions func
	authHandler := AuthHandler{service: service.NewLoginService(authRepo, domain.GetRolePermissions())}

	// create routes - sample URL below using examples GetCustomer, customer_id=1 and account_id=1
	// Sample URL: http://localhost:8181/auth/login?token=validToken&routeName=GetCustomer&customer_id=1&account_id=1
	router.HandleFunc("/auth/login", authHandler.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", authHandler.Verify).Methods(http.MethodGet)

	// grab the server address and port from the environment variables
	serverAddress := os.Getenv("SERVER_ADDRESS")
	serverPort := os.Getenv("SERVER_PORT")

	logger.Info(fmt.Sprintf("OAuth server starting at %s:%s", serverAddress, serverPort))
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", serverAddress, serverPort), router))
}

func envVariablesCheck() error {
	envVariables := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"DB_USER",
		"DB_PASSWD",
		"DB_ADDRESS",
		"DB_PORT",
		"DB_NAME",
	}

	for _, variable := range envVariables {
		if os.Getenv(variable) == "" {
			logger.Error(fmt.Sprintf("missing environment variable %s - application is exiting", variable))
			return fmt.Errorf("missing environment variable %s - application is exiting", variable)
		}
	}

	return nil
}

func getDbClient() *sqlx.DB {
	// grab the relavent environment vairables
	dbUser := os.Getenv("DB_USER")
	dbPasswd := os.Getenv("DB_PASSWD")
	dbAddress := os.Getenv("DB_ADDRESS")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	// create the database connection URL
	db_source := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPasswd, dbAddress, dbPort, dbName)

	// open database connection
	db_conn, err := sqlx.Open("mysql", db_source)
	if err != nil {
		panic(err)
	}

	// set connection parameters
	db_conn.SetConnMaxLifetime(time.Minute * 3)
	db_conn.SetMaxOpenConns(10)
	db_conn.SetMaxIdleConns(10)

	return db_conn
}
