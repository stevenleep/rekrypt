// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stenvenleep/rekrypt/transform-service/rekrypt"
)

const Version = "0.1.0"

type (
	TransformRequest struct {
		EncryptedValue []byte `json:"encrypted_value" binding:"required"`
		TransformKey   []byte `json:"transform_key" binding:"required"`
		SigningKeypair []byte `json:"signing_keypair" binding:"required"`
	}

	TransformResponse struct {
		TransformedValue []byte `json:"transformed_value"`
	}

	ErrorResponse struct {
		Error   string `json:"error"`
		Message string `json:"message,omitempty"`
	}
)

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Printf("%s %s %d %v", c.Request.Method, c.Request.URL.Path,
			c.Writer.Status(), time.Since(start))
	}
}

func main() {
	port := flag.String("port", "8080", "Server port")
	debug := flag.Bool("debug", false, "Debug mode")
	flag.Parse()

	if *debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery(), requestLogger())

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "Rekrypt Transform Service",
			"version": Version,
			"ffi":     rekrypt.Version(),
		})
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Unix(),
		})
	})

	r.POST("/api/transform", func(c *gin.Context) {
		var req TransformRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "invalid_request",
				Message: err.Error(),
			})
			return
		}

		transformed, err := rekrypt.Transform(
			req.EncryptedValue,
			req.TransformKey,
			req.SigningKeypair,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "transform_failed",
				Message: rekrypt.LastError(),
			})
			return
		}

		c.JSON(http.StatusOK, TransformResponse{
			TransformedValue: transformed,
		})
	})

	log.Printf("Rekrypt Transform Service v%s (FFI: %s)", Version, rekrypt.Version())
	log.Printf("Listening on :%s", *port)

	if err := r.Run(":" + *port); err != nil {
		log.Fatal(err)
	}
}
