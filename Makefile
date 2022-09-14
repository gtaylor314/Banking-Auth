run:
	SERVER_ADDRESS=localhost SERVER_PORT=8181 DB_USER=root DB_PASSWD=53cr3t01 DB_ADDRESS=localhost DB_PORT=3306 DB_NAME=banking go run main.go

.PHONY: run