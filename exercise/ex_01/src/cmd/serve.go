/*
Copyright © 2026 Vinzenz Stadtmueller vinzenz.stadtmueller@fh-hagenberg.at
*/
package cmd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// STRUCTS

type Recipe struct {
	gorm.Model
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Ingredients pq.StringArray `gorm:"type:varchar(64)[]" json:"ingredients"`
}

type request struct {
	URL      string      `json:"url"`
	Method   string      `json:"method"`
	Headers  http.Header `json:"headers"`
	Body     []byte      `json:"body"`
	ClientIP string      `json:"client_ip"`
}

// GLOBAL VARS
var db *gorm.DB
var gameSecret = fmt.Sprintf("%d", time.Now().UnixNano())

var fortunes = []string{
	"A watched pot never boils, but an unwatched deploy always crashes.",
	"You will mass-produce spaghetti... code.",
	"The secret ingredient is always butter. And proper error handling.",
	"Today's mass: kubectl delete pod --all. Amen.",
	"A rolling deployment gathers no downtime.",
	"He who controls the Helm chart controls the universe.",
	"404: Fortune not found. Just like your production logs.",
	"SELECT * FROM fortune WHERE luck = true; -- 0 rows returned",
	"You will discover a hidden vulnerability. In production. On Friday.",
	"In the cloud, no one can hear you kubectl exec.",
	"Roses are red, YAML is pain, your indentation is wrong again.",
	"Kubernetes: it's not DNS. There's no way it's DNS. It was DNS.",
	"Your container will run as root today. Just kidding, we fixed that.",
	"Trust no one. Especially not base64 'encryption'.",
}

var asciiChef = `
    _____
   /     \
  | () () |
   \  ^  /
    |||||
    |||||
 .-'|||||'-.     BUON APPETITO!
/   |||||   \
|  /|| ||\  |    Your recipe API is
\ / || || \ /    cooking up something
    || ||        delicious!
    || ||
   _|| ||_
  (__| |__)
`

func gameToken(number int) string {
	mac := hmac.New(sha256.New, []byte(gameSecret))
	mac.Write([]byte(strconv.Itoa(number)))
	return fmt.Sprintf("%d.%s", number^0xCAFE, hex.EncodeToString(mac.Sum(nil))[:16])
}

func verifyToken(token string) (int, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return 0, false
	}
	obfuscated, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, false
	}
	number := obfuscated ^ 0xCAFE
	expected := gameToken(number)
	return number, expected == token
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Runs the server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("serve called")
		gin.SetMode(gin.ReleaseMode)
		var err error

		dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
			viper.GetString("db_host"),
			viper.GetString("db_user"),
			viper.GetString("db_password"),
			viper.GetString("db_name"),
			viper.GetString("db_port"),
		)

		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		err = db.AutoMigrate(&Recipe{})
		if err != nil {
			panic("failed to migrate")
		}

		r := gin.Default()

		r.GET("/", func (c *gin.Context) {
			c.Data(http.StatusOK, "text/plain", []byte("Recipe service"))
		})

		r.GET("/recipes", func(c *gin.Context) {
			var recipes []Recipe
			result := db.Find(&recipes)
			if result.Error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
				return
			}
			c.JSON(http.StatusOK, recipes)
		})

		// Endpoint to return a specific recipe with the given ID
		r.GET("/recipes/:id", func(c *gin.Context) {
			var recipe Recipe
			result := db.First(&recipe, c.Param("id"))
			if result.Error != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "recipe not found"})
				return
			}
			c.JSON(http.StatusOK, recipe)
		})

		// Endpoint to create a new recipe
		r.POST("/recipes", func(c *gin.Context) {
			var recipe Recipe
			err := c.ShouldBindJSON(&recipe)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			result := db.Create(&recipe)
			if result.Error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
				return
			}
			c.JSON(http.StatusOK, recipe)
		})

		// Endpoint to update a specific recipe with the given ID
		r.PUT("/recipes/:id", func(c *gin.Context) {
			var recipe Recipe
			result := db.First(&recipe, c.Param("id"))
			if result.Error != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "recipe not found"})
				return
			}
			err := c.ShouldBindJSON(&recipe)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			result = db.Save(&recipe)
			if result.Error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
				return
			}
			c.JSON(http.StatusOK, recipe)
		})

		// Endpoint to delete a specific recipe with the given ID
		r.DELETE("/recipes/:id", func(c *gin.Context) {
			var recipe Recipe
			result := db.First(&recipe, c.Param("id"))
			if result.Error != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "recipe not found"})
				return
			}
			result = db.Delete(&recipe)
			if result.Error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
				return
			}
			c.Status(http.StatusNoContent)
		})

		// Echo the request
		r.GET("/debug", func(ctx *gin.Context) {
			var err error
			rr := &request{}
			rr.Method = ctx.Request.Method
			rr.Headers = ctx.Request.Header
			rr.URL = ctx.Request.URL.String()
			rr.ClientIP = ctx.ClientIP()
			if err != nil {
				return
			}

			if err != nil {
				return
			}
			ctx.JSON(http.StatusOK, rr)
		})

		// Easter egg: I'm a teapot
		r.GET("/brew", func(c *gin.Context) {
			c.Data(http.StatusTeapot, "text/plain", []byte(`
        ;:'
   _..---.._    .'
 .'  /#####'.  ;
;  ,##/"""\##;  ;
; /##/     \##\.;
 '##|   o  |##'
  \##\     /##/
   '\##\  /##'
     '--''--'
  418: I'm a teapot.
  I refuse to brew coffee.
`))
		})

		// Easter egg: ASCII chef
		r.GET("/chef", func(c *gin.Context) {
			c.Data(http.StatusOK, "text/plain", []byte(asciiChef))
		})

		// Easter egg: recipe fortune cookie
		r.GET("/fortune", func(c *gin.Context) {
			fortune := fortunes[rand.Intn(len(fortunes))]
			c.JSON(http.StatusOK, gin.H{
				"fortune_cookie": fortune,
			})
		})

		// Easter egg: number guessing game
		r.GET("/game", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Welcome to the Recipe Number Guessing Game!",
				"instructions": []string{
					"POST /game/new to start a new game (I'll pick a number 1-100)",
					"POST /game/guess with {\"token\": \"...\", \"guess\": 42} to make a guess",
					"Can you find the secret ingredient (number)?",
				},
			})
		})

		r.POST("/game/new", func(c *gin.Context) {
			number := rand.Intn(100) + 1
			token := gameToken(number)
			c.JSON(http.StatusOK, gin.H{
				"message":  "I'm thinking of a number between 1 and 100...",
				"token":    token,
				"attempts": 0,
				"hint":     "POST /game/guess with {\"token\": \"<token>\", \"guess\": <your_number>}",
			})
		})

		r.POST("/game/guess", func(c *gin.Context) {
			var body struct {
				Token string `json:"token"`
				Guess int    `json:"guess"`
			}
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Send {\"token\": \"...\", \"guess\": 42}"})
				return
			}
			target, valid := verifyToken(body.Token)
			if !valid {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired token. Start a new game with POST /game/new"})
				return
			}
			switch {
			case body.Guess < target:
				c.JSON(http.StatusOK, gin.H{
					"result":  "too_low",
					"message": "Too low! The secret ingredient needs more heat!",
					"token":   body.Token,
				})
			case body.Guess > target:
				c.JSON(http.StatusOK, gin.H{
					"result":  "too_high",
					"message": "Too high! Reduce the temperature!",
					"token":   body.Token,
				})
			default:
				c.JSON(http.StatusOK, gin.H{
					"result":  "correct",
					"message": fmt.Sprintf("You got it! The secret ingredient was %d! You're a master chef!", target),
					"trophy":  "( * ^ *) ~~ CONGRATULATIONS ~~",
				})
			}
		})

		// Check for database connection
		r.GET("/health", func(c *gin.Context) {
			if d, ok := db.DB(); ok == nil {
				if err = d.Ping(); err != nil {
					c.AbortWithStatus(http.StatusInternalServerError)
					return
				}
			} else {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			c.Status(http.StatusOK)
		})

		err = r.Run(":8080")
		if err != nil {
			panic("error starting the server")
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
