// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

type CreateUserInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
	Usertype string `json:"usertype"`
}

type CreateUserOutput struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Usertype string `json:"usertype"`
}

type Mutation struct {
}

type Query struct {
}

type User struct {
	ID           string `json:"_id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Usertype     string `json:"usertype"`
	CreatedAt    string `json:"created_at"`
	LastLoggedIn string `json:"last_logged_in"`
}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginOutput struct {
	Token  string `json:"token"`
	Status bool   `json:"status"`
}

type UpdatePasswordInput struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	NewPassword string `json:"newPassword"`
}

type UpdatePasswordOutput struct {
	Message string `json:"message"`
	Status  bool   `json:"status"`
}