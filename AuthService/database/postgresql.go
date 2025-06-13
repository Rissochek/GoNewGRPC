package database

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"AuthProject/model"
	"AuthProject/utils"
)

func InitDataBase() *gorm.DB {
	dsn := "host=localhost user=riss password=123 dbname=authdb port=9001 sslmode=disable TimeZone=Europe/Moscow"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to init DB: %v", err)
	}
	db.AutoMigrate(&model.User{})
	return db
}

func AddUserToDataBase(db *gorm.DB, user *model.User) error {
	if (user.Usermame == "" || user.Password == "") {
		return fmt.Errorf("incorrect json structure")
	}
	hashed_user_password := utils.GenerateHash(user.Password)
	user.Password = hashed_user_password

	result := db.Create(user)
	if result != nil {
		return result.Error
	}
	return nil
}

func SearchUserInDB(db *gorm.DB, user *model.User) (model.User, error) {
	if (user.Usermame == "" || user.Password == "") {
		return model.User{}, fmt.Errorf("incorrect json structure")
	}
	target_user := model.User{}
	if err := db.Where(&model.User{Usermame: user.Usermame}).First(&target_user).Error; err != nil {
		return model.User{}, err
	}
	err := utils.CompareHashAndPassword(user.Password, target_user.Password)
	return target_user, err
}	
