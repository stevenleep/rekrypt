// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

package main

/*
#cgo LDFLAGS: -L./lib -lrekrypt_transform
#include <stdlib.h>

extern int transform(
    const unsigned char* capsule_ptr, size_t capsule_len,
    const unsigned char* transform_key_ptr, size_t transform_key_len,
    unsigned char* out_ptr, size_t out_len
);

extern size_t get_output_buffer_size();
*/
import "C"
import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"unsafe"

	"github.com/gin-gonic/gin"
)

// TransformRequest 转换请求
// 注意：capsule 是完整的 Capsule 对象（序列化后），不是 EncryptedValue
type TransformRequest struct {
	Capsule      string `json:"capsule" binding:"required"`       // 序列化的完整 Capsule 对象
	TransformKey string `json:"transform_key" binding:"required"` // 序列化的 TransformKey
}

// TransformResponse 转换响应
type TransformResponse struct {
	TransformedCapsule string `json:"transformed_capsule"` // 转换后的完整 Capsule 对象
}

// Transform 执行代理重加密转换
// 输入：序列化的 Capsule 对象 + TransformKey
// 输出：转换后的 Capsule 对象（encrypted_data 字段已被转换）
func Transform(capsule, transformKey []byte) ([]byte, error) {
	// 验证输入
	if len(capsule) == 0 {
		return nil, errors.New("empty capsule")
	}
	if len(transformKey) == 0 {
		return nil, errors.New("empty transform key")
	}

	// 获取输出缓冲区大小
	bufferSize := int(C.get_output_buffer_size())
	outBuffer := make([]byte, bufferSize)

	// 调用 Rust FFI
	// 注意：不再需要 signing_key_pair 参数，因为它包含在 capsule 中
	result := C.transform(
		(*C.uchar)(unsafe.Pointer(&capsule[0])),
		C.size_t(len(capsule)),
		(*C.uchar)(unsafe.Pointer(&transformKey[0])),
		C.size_t(len(transformKey)),
		(*C.uchar)(unsafe.Pointer(&outBuffer[0])),
		C.size_t(bufferSize),
	)

	// 检查错误
	if result < 0 {
		switch result {
		case -1:
			return nil, errors.New("failed to deserialize capsule")
		case -2:
			return nil, errors.New("failed to deserialize encrypted_value from capsule")
		case -3:
			return nil, errors.New("failed to deserialize transform key")
		case -4:
			return nil, errors.New("failed to deserialize signing keypair from capsule")
		case -5:
			return nil, errors.New("transform operation failed")
		case -6:
			return nil, errors.New("failed to serialize transformed encrypted_value")
		case -7:
			return nil, errors.New("failed to serialize transformed capsule")
		case -8:
			return nil, errors.New("output buffer too small")
		default:
			return nil, errors.New("unknown error")
		}
	}

	// 返回转换后的 Capsule
	return outBuffer[:result], nil
}

func main() {
	// 配置
	port := getEnv("PORT", "8080")
	mode := getEnv("GIN_MODE", "release")

	gin.SetMode(mode)
	r := gin.Default()

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// 服务信息
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service":     "REKRYPT Proxy Re-encryption Service",
			"version":     "1.0.0",
			"description": "Stateless proxy service for cryptographic re-encryption transformations",
		})
	})

	// 转换端点
	r.POST("/transform", func(c *gin.Context) {
		var req TransformRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
			return
		}

		// 解码 base64
		capsule, err := base64.StdEncoding.DecodeString(req.Capsule)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid capsule encoding"})
			return
		}

		transformKey, err := base64.StdEncoding.DecodeString(req.TransformKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid transform_key encoding"})
			return
		}

		// 执行转换
		transformedCapsule, err := Transform(capsule, transformKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "transform failed: " + err.Error()})
			return
		}

		// 返回结果
		c.JSON(http.StatusOK, gin.H{
			"transformed_capsule": base64.StdEncoding.EncodeToString(transformedCapsule),
		})
	})

	// 启动服务
	log.Printf("Starting REKRYPT proxy service on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
