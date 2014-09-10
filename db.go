package main

import (
	"database/sql"
	"errors"
	_ "github.com/go-sql-driver/mysql"
	"strconv"
	"time"
)

var (
	dbcon          *sql.DB = nil
)

func dbInit(hostname, username, password, dbname string) error {
	var (
		err error
	)
	if dbcon != nil {
		dbcon.Close()
	}
	dsn := username + ":" + password + "@tcp(" + hostname + ":" + strconv.Itoa(sqlPort) + ")/" + dbname
	dbcon, err = sql.Open("mysql", dsn)
	return err
}

func dbRegisterDomain(domain string, dstIP string, accessKey string, submitIP string) error {
	var (
		err error
	)
	exists, err := dbDomainExists(domain)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("Domain already exists")
	}
	query := "insert into host_registry (hostname, access_key, submit_ip, locked, created) values (?, ?, ?, ?, ?)"
	_, err = dbcon.Exec(query, domain, accessKey, submitIP, 0, time.Now().Unix())
	if err != nil {
		return err
	}
	query = "insert into host_records (hostname, dst_ip, submit_ip, updated, created) values (?, ?, ?, ?, ?)"
	now := time.Now().Unix()
	_, err = dbcon.Exec(query, domain, dstIP, submitIP, 0, now)
	if err != nil {
		return err
	}
	return nil
}

func dbGetAccessKey(domain string) (string, error) {
	var (
		key string
		err error
		query string = "select access_key from host_registry where hostname=?"
	)
	err = dbcon.QueryRow(query, domain).Scan(&key)
	switch {
	case err == sql.ErrNoRows:
		err = nil
		key = ""
	case err != nil:
		key = ""
	}
	return key, err
}

func dbDomainExists(domain string) (bool, error) {
	key, err := dbGetAccessKey(domain)
	if err != nil {
		return false, err
	}
	if len(key) == 0 {
		return false, nil
	}
	return true, nil
}

func dbGetDomainDstIP(domain string) (string, error) {
	var (
		dstIP string
		err error
		query string = "select dst_ip from host_records where hostname=?"
	)
	err = dbcon.QueryRow(query, domain).Scan(&dstIP)
	switch {
	case err == sql.ErrNoRows:
		err = nil
		dstIP = ""
	case err != nil:
		dstIP = ""
	}
	return dstIP, err
}

func dbUpdateDomain(domain string, dstIP string, accessKey string, submitIP string) (bool, error) {
	var (
		query string
	)
	dbKey, err := dbGetAccessKey(domain)
	if err != nil {
		return false, err
	}
	if len(dbKey) == 0 || accessKey != dbKey {
		return false, errors.New("Invalid key")
	}
	dbDstIP, err := dbGetDomainDstIP(domain)
	if err != nil {
		return false, err
	}
	if dbDstIP == dstIP {
		return false, nil
	} else if dbDstIP != "" {
		query = "update host_records set dst_ip=?, submit_ip=?, updated=? where hostname=?"
		_, err := dbcon.Exec(query, dstIP, submitIP, time.Now().Unix(), domain)
		if err != nil {
			return false, err
		}
	} else {
		query = "insert into host_records (hostname, dst_ip, submit_ip, updated, created) values (?, ?, ?, ?, ?)"
		now := time.Now().Unix()
		_, err = dbcon.Exec(query, domain, dstIP, submitIP, now, now)
		if err != nil {
			return false, err
		}
	}
	return true, err
}
