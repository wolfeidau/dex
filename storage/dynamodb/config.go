package dynamodb

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"

	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/storage"
)

type DynamoDB struct {
	TableName         string  `json:"endpoint" yaml:"table_name"`
	Endpoint          *string `json:"endpoint" yaml:"endpoints"`
	Region            *string `json:"endpoint" yaml:"region"`
	AccessKey         *string `json:"endpoint" yaml:"aws_access_key_id"`
	SecretAccessKey   *string `json:"endpoint" yaml:"aws_secret_access_key"`
	SecretAccessToken *string `json:"endpoint" yaml:"aws_secret_access_token"`
}

func (ddb *DynamoDB) Open(logger log.Logger) (storage.Storage, error) {
	if ddb.Endpoint != nil {
		creds := credentials.NewStaticCredentials(aws.StringValue(ddb.AccessKey), aws.StringValue(ddb.SecretAccessKey), aws.StringValue(ddb.SecretAccessToken))

		return New(logger, ddb.TableName, &aws.Config{
			Region:      ddb.Region,
			Endpoint:    ddb.Endpoint,
			Credentials: creds,
		}), nil
	}

	return New(logger, ddb.TableName), nil
}
