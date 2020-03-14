package dynamodb

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/dynamodb"

	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/storage"
)

// DynamoDB holds the configuration for dynamodb
type DynamoDB struct {
	TableName         string  `json:"table_name" yaml:"table_name"`
	Endpoint          *string `json:"endpoint" yaml:"endpoint"`
	Region            *string `json:"region" yaml:"region"`
	AccessKey         *string `json:"aws_access_key_id" yaml:"aws_access_key_id"`
	SecretAccessKey   *string `json:"aws_secret_access_key" yaml:"aws_secret_access_key"`
	SecretAccessToken *string `json:"aws_secret_access_token" yaml:"aws_secret_access_token"`
}

// Open create a new instance of the DynamoDB storage driver
func (ddb *DynamoDB) Open(logger log.Logger) (storage.Storage, error) {
	logger.Warnf("endpoint: %s", ddb.Endpoint)
	if ddb.Endpoint != nil {
		creds := credentials.NewStaticCredentials(aws.StringValue(ddb.AccessKey), aws.StringValue(ddb.SecretAccessKey), aws.StringValue(ddb.SecretAccessToken))

		s := New(logger, ddb.TableName, &aws.Config{
			Region:      ddb.Region,
			Endpoint:    ddb.Endpoint,
			Credentials: creds,
		})

		ddbs := s.(*dynamodbStorage)

		err := ddbs.createTable(dynamodb.BillingModeProvisioned, &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(1),
			WriteCapacityUnits: aws.Int64(1),
		})
		if err != nil {
			return nil, err
		}

		return s, nil
	}

	return New(logger, ddb.TableName), nil
}
