package dynamodb

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/conformance"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

const testDynamoDBEnv = "DEX_DYNAMODB_ENDPOINT"

func cleanDB(c *dynamodbStorage) error {
	return c.dropTable()
}

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{DisableColors: true},
	Level:     logrus.DebugLevel,
}

func TestDynamoDB(t *testing.T) {

	assert := require.New(t)

	endpointsStr := os.Getenv(testDynamoDBEnv)

	if endpointsStr == "" {
		t.Skipf("test environment variable %q not set, skipping", testDynamoDBEnv)
		return
	}

	ddbStorage := &DynamoDB{
		TableName:       "test_table",
		Endpoint:        aws.String(endpointsStr),
		Region:          aws.String("us-east-1"),
		AccessKey:       aws.String("test"),
		SecretAccessKey: aws.String("test"),
	}

	ds, err := ddbStorage.Open(logger)
	assert.NoError(err)
	if v, ok := ds.(*dynamodbStorage); ok {
		err = v.dropTable()
		assert.NoError(err)
		err = v.createTable(dynamodb.BillingModeProvisioned, &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(1),
			WriteCapacityUnits: aws.Int64(1),
		})
	}

	newStorage := func() storage.Storage {
		return ds
	}

	conformance.RunTests(t, newStorage)
	conformance.RunTransactionTests(t, newStorage)
}
