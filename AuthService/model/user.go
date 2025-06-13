package model

type User struct{
	UserId 	 uint 	`gorm:"primaryKey;autoIncrement"`
	Usermame string `json:"username" gorm:"uniqueIndex"`
	Password string `json:"password"`
}