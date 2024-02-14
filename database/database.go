package database

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/ashbeelghouri/user-authentication/graph/model"
	utilities "github.com/ashbeelghouri/user-authentication/utilities"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var dbName = "practice"

var connectionString string = "mongodb://localhost:27017/" + dbName

type DB struct {
	client *mongo.Client
}

func Connect() *DB {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(connectionString))
	if err != nil {
		log.Fatal(err)
	}
	err = client.Ping(ctx, readpref.Primary())

	if err != nil {
		log.Fatal(err)
	}

	return &DB{
		client: client,
	}
}

func (db *DB) CreateUser(userInfo model.CreateUserInput) *model.CreateUserOutput {
	userCollection := db.client.Database(dbName).Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	encryptedPassword, err := utilities.HashPassword(userInfo.Password)
	if err != nil {
		log.Fatal(err)
	}
	inserted, err := userCollection.InsertOne(ctx, bson.M{
		"email":          userInfo.Email,
		"username":       userInfo.Username,
		"name":           userInfo.Name,
		"password":       encryptedPassword,
		"usertype":       userInfo.Usertype,
		"created_at":     time.Now(),
		"last_logged_in": time.Now(),
	})
	if err != nil {
		log.Fatal(err)
	}

	insertedID := inserted.InsertedID.(primitive.ObjectID).Hex()

	response := model.CreateUserOutput{
		ID:       insertedID,
		Name:     userInfo.Name,
		Email:    userInfo.Email,
		Username: userInfo.Username,
		Usertype: userInfo.Usertype,
	}

	return &response
}

func (db *DB) UpdateUserPassword(userInfo *model.UpdatePasswordInput) *model.UpdatePasswordOutput {
	userCollection := db.client.Database(dbName).Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	user, err := db.GetUserByUserName(userInfo.Username)

	if err != nil {
		log.Fatal(err)
	}

	if utilities.CheckPasswordHash(userInfo.Password, user.Password) == true {
		updateInfo := bson.M{}
		encryptedPassword, err := utilities.HashPassword(userInfo.NewPassword)
		if err != nil {
			log.Fatal(err)
		}
		updateInfo["password"] = encryptedPassword
		filter := bson.M{"username": userInfo.Username}
		update := bson.M{"$set": updateInfo}

		results := userCollection.FindOneAndUpdate(ctx, filter, update)
		var userDetails model.User
		if err := results.Decode(&userDetails); err != nil {
			log.Fatal(err)
		}

		return &model.UpdatePasswordOutput{
			Message: "user password updated",
			Status:  true,
		}
	}

	return &model.UpdatePasswordOutput{
		Message: "unable to update the password",
		Status:  true,
	}
}

func (db *DB) GetUsers() []*model.User {
	userCollection := db.client.Database(dbName).Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var allUsers []*model.User
	cursor, err := userCollection.Find(ctx, bson.D{})
	if err != nil {
		log.Fatal(err)
	}
	if err = cursor.All(context.TODO(), &allUsers); err != nil {
		panic(err)
	}
	return allUsers
}

func (db *DB) GetUserByUserName(username string) (*model.User, error) {
	userCollection := db.client.Database(dbName).Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	filter := bson.M{
		"username": username,
	}
	var userDetails model.User
	err := userCollection.FindOne(ctx, filter).Decode(&userDetails)
	if err != nil {
		return nil, err
	}
	return &userDetails, nil
}

func (db *DB) GetUserByEmail(email string) (*model.User, error) {
	userCollection := db.client.Database(dbName).Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	filter := bson.M{
		"email": email,
	}
	var userDetails model.User
	err := userCollection.FindOne(ctx, filter).Decode(&userDetails)
	if err != nil {
		return nil, err
	}
	return &userDetails, nil
}

func (db *DB) LoginUser(loginInfo model.LoginInput) *model.LoginOutput {
	user, err := db.GetUserByUserName(loginInfo.Username)
	if err != nil {
		user, err = db.GetUserByEmail((loginInfo.Username))
	}

	if err != nil {
		log.Fatal(err)
	}

	tokenJSON, err := json.Marshal(user)
	if err != nil {
		log.Fatal(err)
	}
	tokenStr := string(tokenJSON)

	if utilities.CheckPasswordHash(loginInfo.Password, user.Password) == true {
		token, err := utilities.CreateToken(tokenStr, 2*time.Hour)
		if err != nil {
			log.Fatal(err)
		}
		response := model.LoginOutput{
			Token:  token,
			Status: true,
		}
		return &response
	}
	response := model.LoginOutput{
		Token:  "",
		Status: false,
	}

	return &response
}
