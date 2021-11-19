package main

import (
	"errors"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

type Image struct {
	gorm.Model
	ID     string
	Author User `gorm:"embedded"`
}

type User struct {
	ID       string
	Username string
	Password string
}

func InitDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("database.db"), &gorm.Config{})
	if err != nil {
		panic("could not open db")
	}

	db.AutoMigrate(&User{}, &Image{})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func RegisterUserDB(username string, password string) error {
	var existing User
	db.First(&existing, "username = ?", username)
	if existing.ID != "" {
		return errors.New("already exists")
	}

	id := uuid.New()
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return err
	}

	err = db.Create(&User{
		ID:       id.String(),
		Username: username,
		Password: hashedPassword,
	}).Error

	return err
}

func LoginUserDB(username string, password string) (*User, error) {
	var user User
	db.First(&user, "username = ?", username)

	corr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	return &user, corr
}
