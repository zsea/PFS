package main

import (
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func LoggerInitialization() {

	logger = zap.NewExample().Sugar()

}
