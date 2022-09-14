package domain

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gtaylor314/Banking-Lib/errs"
	"github.com/gtaylor314/Banking-Lib/logger"
	"github.com/jmoiron/sqlx"
)

type AuthRepository interface {
	FindBy(username string, password string) (*Login, *errs.AppError)
}

type AuthRepositoryDb struct {
	db_conn *sqlx.DB
}

func (repo AuthRepositoryDb) FindBy(username string, password string) (*Login, *errs.AppError) {
	var login Login
	// sqlQuery grabs the username, customer_id, role and account ids for a specified username and password
	// the users table has an alias "u" and the accounts table has an alias "a" - the two tables are joined where the
	// customer id in users matches the customer id in accounts - the account ids are then grouped under an account_numbers
	// column (separated by a comma) for the customer id
	sqlQuery := `SELECT username, u.customer_id, role, group_concat(a.account_id) as account_numbers FROM users u 
				 LEFT JOIN accounts a ON a.customer_id = u.customer_id
				 WHERE username = ? AND password = ?
				 GROUP BY username, a.customer_id`
	// Get() runs the sqlQuery and stores the result in the destination (login *Login)
	err := repo.db_conn.Get(&login, sqlQuery, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Error("invalid username or password - no account found " + err.Error())
			return nil, errs.AuthorizationErr("invalid username or password")
		}
		logger.Error("error running query and populating login " + err.Error())
		return nil, errs.UnexpectedErr("unexpected error querying database")
	}
	return &login, nil
}

func NewAuthRepository(db_conn *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{db_conn: db_conn}
}
