package jwtwithnosql

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	ID    primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Name  string             `json:"name" bson:"name"`
	Email string             `json:"email" bson:"email"`
}

type RedisInstance struct {
	Client *redis.Client
}
type MongoInstance struct {
	Client *mongo.Client
	DB     *mongo.Database
	User   *mongo.Collection
}

type HybridHandler struct {
	Redis *RedisInstance
	Mongo *MongoInstance
	Ctx   context.Context
}

type Claims struct {
	Email     string `json:"email"`
	TokenType string `json:"token_type"` // "access" or "refresh" token
	jwt.RegisteredClaims
}

type Crediantials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func ConnectRedis() (*RedisInstance, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_ADDR"),
		DB:   0,
	})
	return &RedisInstance{Client: rdb}, nil
}

func ConnectMongoDB() (*MongoInstance, error) {
	ClientOptions := options.Client().ApplyURI(os.Getenv("MONGO_URI"))
	client, err := mongo.NewClient(ClientOptions)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}
	db := client.Database(os.Getenv("MONGO_DB"))
	return &MongoInstance{
		Client: client,
		DB:     db,
		User:   db.Collection("users"),
	}, nil
}

var Secretkey []byte

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
)

// Generate access token
func GenerateAccessToken(email string) (string, error) {
	claims := &Claims{
		Email:     email,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(Secretkey)

}

// Generate refresh token
func GenerateRefreshToken(email string) (string, error) {
	claims := &Claims{
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(Secretkey)

}

// Login
func Login(h *HybridHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds Crediantials
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "failed to decode response:", http.StatusInternalServerError)
			return
		}
		if creds.Email != "akashpaul4790@gmail.com" || creds.Password != "Akash@479" {
			http.Error(w, "Invalid crediantials", http.StatusUnauthorized)
			return
		}
		accesstoken, _ := GenerateAccessToken(creds.Email)
		refreshtoken, _ := GenerateRefreshToken(creds.Email)

		h.Redis.Client.Set(h.Ctx, "refresh:"+refreshtoken, creds.Email, refreshTokenTTL)

		json.NewEncoder(w).Encode(map[string]string{"access_token": accesstoken, "refresh_token": refreshtoken})
	}
}

// Refresh
func Refresh(h *HybridHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid body", http.StatusInternalServerError)
			return
		}
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(body.RefreshToken, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method")
			}
			return Secretkey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
			return
		}
		if claims.TokenType != "refresh" {
			http.Error(w, "Invalid token type", http.StatusUnauthorized)
			return
		}
		email, err := h.Redis.Client.Get(h.Ctx, "refresh:"+body.RefreshToken).Result()
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		newaccesstoken, _ := GenerateAccessToken(email)
		json.NewEncoder(w).Encode(map[string]string{"access_token": newaccesstoken})
	}
}

// JWTMiddleware
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		tokenstr := strings.TrimPrefix(auth, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenstr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return Secretkey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "invalid token!", http.StatusUnauthorized)
			return
		}
		if claims.TokenType != "access" {
			http.Error(w, "Invalid token type", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Logut
func Logout(h *HybridHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Refreshtoken string `json:"refresh_token"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		h.Redis.Client.Del(h.Ctx, "refresh:"+body.Refreshtoken)
		w.Write([]byte("Logged out!"))
	}
}

// Validation
func ValidUser(user User) error {
	if strings.TrimSpace(user.Name) == "" {
		return fmt.Errorf("name is invalid and empty")
	}
	if strings.TrimSpace(user.Email) == "" {
		return fmt.Errorf("email is empty and invalid ")
	}
	if !strings.HasSuffix(user.Email, "@gmail.com") {
		return fmt.Errorf("email is invalid and does not contain @gmail.com")
	}
	prefix := strings.TrimSuffix(user.Email, "@gmail.com")
	if prefix == "" {
		return fmt.Errorf("email must contains a prefix before @gmail.com")
	}
	return nil
}

// Create user
func (h *HybridHandler) CreateUserHandlers(w http.ResponseWriter, r *http.Request) {
	var users User
	if err := json.NewDecoder(r.Body).Decode(&users); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := ValidUser(users); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"Error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(h.Ctx, 5*time.Second)
	defer cancel()

	res, err := h.Mongo.User.InsertOne(ctx, users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users.ID = res.InsertedID.(primitive.ObjectID)

	jsonData, _ := json.Marshal(users)
	h.Redis.Client.Set(h.Ctx, users.ID.Hex(), jsonData, 10*time.Minute)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(users)

}

// Get user
func (h *HybridHandler) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	value, err := h.Redis.Client.Get(h.Ctx, id).Result()
	if err == nil {
		log.Println("Cache hit")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(value))
		return
	}
	log.Println("cache miss, querying MongoDB...")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, "invalid id format", http.StatusBadRequest)
		return
	}
	var users User
	ctx, cancel := context.WithTimeout(h.Ctx, 5*time.Second)
	defer cancel()

	err = h.Mongo.User.FindOne(ctx, bson.M{"_id": objID}).Decode(&users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsondata, err := json.Marshal(users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Redis.Client.Set(h.Ctx, id, jsondata, 10*time.Minute)

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsondata)
}

// Update user
func (h *HybridHandler) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var users User
	if err := json.NewDecoder(r.Body).Decode(&users); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := ValidUser(users); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"Error": err.Error()})
		return
	}
	objID, _ := primitive.ObjectIDFromHex(id)
	ctx, cancel := context.WithTimeout(h.Ctx, 5*time.Second)
	defer cancel()
	update := bson.M{
		"$set": bson.M{
			"name":  users.Name,
			"email": users.Email,
		},
	}
	res, err := h.Mongo.User.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if res.MatchedCount == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	users.ID = objID
	jsonData, err := json.Marshal(users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.Redis.Client.Set(h.Ctx, id, jsonData, 10*time.Minute)

	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// Delete user
func (h *HybridHandler) DeleteuserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	objID, _ := primitive.ObjectIDFromHex(id)
	ctx, cancel := context.WithTimeout(h.Ctx, 5*time.Second)
	defer cancel()

	res, err := h.Mongo.User.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if res.DeletedCount == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
	}

	h.Redis.Client.Del(h.Ctx, id)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("user Deleted!"))

}

// main func
func CrudOperationWithMOngoDBUsingJWT() {
	godotenv.Load()
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatalf("JWT_SECRET is not set or empty")
	}
	Secretkey = []byte(secret)

	redisinstance, err := ConnectRedis()
	if err != nil {
		panic(err)
	}
	mongoinstance, err := ConnectMongoDB()
	if err != nil {
		panic(err)
	}
	handler := &HybridHandler{Redis: redisinstance, Mongo: mongoinstance, Ctx: context.Background()}

	r := mux.NewRouter()

	r.HandleFunc("/login", Login(handler)).Methods("POST")
	r.HandleFunc("/refresh", Refresh(handler)).Methods("POST")
	r.HandleFunc("/logout", Logout(handler)).Methods("POST")

	api := r.PathPrefix("/api").Subrouter()
	api.Use(JWTMiddleware)

	api.HandleFunc("/users", handler.CreateUserHandlers).Methods("POST")
	api.HandleFunc("/users/{id}", handler.GetUserHandler).Methods("GET")
	api.HandleFunc("/users/{id}", handler.UpdateUserHandler).Methods("PUT")
	api.HandleFunc("/users/{id}", handler.DeleteuserHandler).Methods("DELETE")

	fmt.Println("Server running on port:8080")
	http.ListenAndServe(":8080", r)
}
