#!/bin/sh
aws dynamodb create-table --table-name Cats --attribute-definitions AttributeName=Age,AttributeType=N AttributeName=CatName,AttributeType=S --key-schema AttributeName=Age,KeyType=HASH AttributeName=CatName,KeyType=RANGE --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
