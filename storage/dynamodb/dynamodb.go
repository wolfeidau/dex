package dynamodb

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	dexp "github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/storage"
	"github.com/pkg/errors"
)

const (
	clientPartition         = "client"
	authCodePartition       = "auth_code"
	refreshTokenPartition   = "refresh_token"
	deviceTokenPartition    = "device_token"
	authRequestPartition    = "auth_req"
	deviceRequestPartition  = "device_req"
	passwordPartition       = "password"
	offlineSessionPartition = "offline_session"
	connectorPartition      = "connector"
	keysPartition           = "keys"
	keysID                  = "openid-connect"
)

// New create a new storage instance for DynamoDB
func New(logger log.Logger, tableName string, config ...*aws.Config) storage.Storage {
	sess := session.Must(session.NewSession(config...))

	return &dynamodbStorage{
		tableName: tableName,
		ddb:       dynamodb.New(sess),
		logger:    logger,
	}
}

// dynamodbStorage uses a single dynamodb table to store all the data used by dex
type dynamodbStorage struct {
	tableName string
	ddb       dynamodbiface.DynamoDBAPI

	logger log.Logger
}

func (ds *dynamodbStorage) Close() error {
	return nil
}

func (ds *dynamodbStorage) CreateClient(client storage.Client) error {
	return ds.create(clientPartition, fromStorageClient(client))
}

func (ds *dynamodbStorage) CreateAuthRequest(authRequest storage.AuthRequest) error {
	return ds.create(authRequestPartition, fromStorageAuthRequest(authRequest))
}

func (ds *dynamodbStorage) CreateAuthCode(authCode storage.AuthCode) error {
	return ds.create(authCodePartition, fromStorageAuthCode(authCode))
}

func (ds *dynamodbStorage) CreateRefresh(refreshToken storage.RefreshToken) error {
	return ds.create(refreshTokenPartition, fromStorageRefreshToken(refreshToken))
}

func (ds *dynamodbStorage) CreatePassword(password storage.Password) error {
	return ds.create(passwordPartition, fromStoragePassword(password))
}

func (ds *dynamodbStorage) CreateOfflineSessions(offlineSession storage.OfflineSessions) error {
	return ds.create(offlineSessionPartition, fromStorageOfflineSessions(offlineSession))
}

func (ds *dynamodbStorage) CreateConnector(connector storage.Connector) error {
	return ds.create(connectorPartition, fromStorageConnector(connector))
}

func (ds *dynamodbStorage) CreateDeviceRequest(deviceRequest storage.DeviceRequest) error {
	return ds.create(deviceRequestPartition, fromStorageDeviceRequest(deviceRequest))
}

func (ds *dynamodbStorage) CreateDeviceToken(deviceToken storage.DeviceToken) error {
	return ds.create(deviceTokenPartition, fromStorageDeviceToken(deviceToken))
}

func (ds *dynamodbStorage) GetAuthRequest(id string) (storage.AuthRequest, error) {
	var authRequest AuthRequest

	err := ds.getByID(authRequestPartition, id, &authRequest)
	if err != nil {
		return storage.AuthRequest{}, err
	}

	return toStorageAuthRequest(authRequest), nil
}

func (ds *dynamodbStorage) GetAuthCode(id string) (storage.AuthCode, error) {
	var authCode AuthCode

	err := ds.getByID(authCodePartition, id, &authCode)
	if err != nil {
		return storage.AuthCode{}, err
	}

	ds.logger.Infof("found %+v", authCode)

	return toStorageAuthCode(authCode), nil
}

func (ds *dynamodbStorage) GetClient(id string) (storage.Client, error) {
	var client Client

	err := ds.getByID(clientPartition, id, &client)
	if err != nil {
		return storage.Client{}, err
	}

	return toStorageClient(client), nil
}

func (ds *dynamodbStorage) GetKeys() (storage.Keys, error) {
	var keys Keys

	err := ds.getByID(keysPartition, keysID, &keys)
	if err != nil {
		return storage.Keys{}, err
	}

	return toStorageKeys(keys)
}

func (ds *dynamodbStorage) GetRefresh(id string) (storage.RefreshToken, error) {
	var refreshToken RefreshToken

	err := ds.getByID(refreshTokenPartition, id, &refreshToken)
	if err != nil {
		return storage.RefreshToken{}, err
	}

	return toStorageRefreshToken(refreshToken), nil
}

func (ds *dynamodbStorage) GetPassword(email string) (storage.Password, error) {
	var password Password

	err := ds.getByID(passwordPartition, strings.ToLower(email), &password)
	if err != nil {
		return storage.Password{}, err
	}

	ds.logger.Infof("got record %+v", toStoragePassword(password))

	return toStoragePassword(password), nil
}

func (ds *dynamodbStorage) GetOfflineSessions(userID string, connID string) (storage.OfflineSessions, error) {
	var offlineSession OfflineSessions

	id := fmt.Sprintf("%s/%s", userID, connID)

	err := ds.getByID(offlineSessionPartition, id, &offlineSession)
	if err != nil {
		return storage.OfflineSessions{}, err
	}

	return toStorageOfflineSessions(offlineSession), nil
}

func (ds *dynamodbStorage) GetConnector(id string) (storage.Connector, error) {
	var connector Connector

	err := ds.getByID(connectorPartition, id, &connector)
	if err != nil {
		return storage.Connector{}, err
	}

	return toStorageConnector(connector), nil
}

func (ds *dynamodbStorage) GetDeviceRequest(userCode string) (storage.DeviceRequest, error) {
	var deviceRequest DeviceRequest

	err := ds.getByID(deviceRequestPartition, userCode, &deviceRequest)
	if err != nil {
		return storage.DeviceRequest{}, err
	}

	return toStorageDeviceRequest(deviceRequest), nil
}
func (ds *dynamodbStorage) GetDeviceToken(deviceCode string) (storage.DeviceToken, error) {
	var deviceToken DeviceToken

	err := ds.getByID(deviceTokenPartition, deviceCode, &deviceToken)
	if err != nil {
		return storage.DeviceToken{}, err
	}

	return toStorageDeviceToken(deviceToken), nil
}

func (ds *dynamodbStorage) ListClients() ([]storage.Client, error) {
	items, err := ds.list(clientPartition)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list %s", clientPartition)
	}

	clients := make([]storage.Client, len(items))

	for n, item := range items {
		var client Client

		err = dynamodbattribute.UnmarshalMap(item, &client)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal %v", item)
		}

		clients[n] = toStorageClient(client)
	}

	return clients, nil
}

func (ds *dynamodbStorage) ListRefreshTokens() ([]storage.RefreshToken, error) {
	items, err := ds.list(refreshTokenPartition)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list %s", refreshTokenPartition)
	}

	refreshTokens := make([]storage.RefreshToken, len(items))

	for n, item := range items {
		var refreshToken RefreshToken

		err = dynamodbattribute.UnmarshalMap(item, &refreshToken)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal %v", item)
		}

		refreshTokens[n] = toStorageRefreshToken(refreshToken)
	}

	return refreshTokens, nil
}

func (ds *dynamodbStorage) ListPasswords() ([]storage.Password, error) {
	items, err := ds.list(passwordPartition)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list %s", passwordPartition)
	}

	passwords := make([]storage.Password, len(items))

	for n, item := range items {
		var pw Password

		err = dynamodbattribute.UnmarshalMap(item, &pw)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal %v", item)
		}

		passwords[n] = toStoragePassword(pw)
	}

	return passwords, nil
}

func (ds *dynamodbStorage) ListConnectors() ([]storage.Connector, error) {
	items, err := ds.list(connectorPartition)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list %s", connectorPartition)
	}

	connectors := make([]storage.Connector, len(items))

	for n, item := range items {
		var connector Connector

		err = dynamodbattribute.UnmarshalMap(item, &connector)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal %v", item)
		}

		connectors[n] = toStorageConnector(connector)
	}

	return connectors, nil
}

func (ds *dynamodbStorage) DeleteAuthRequest(id string) error {
	return ds.delete(authRequestPartition, id)
}

func (ds *dynamodbStorage) DeleteAuthCode(code string) error {
	return ds.delete(authCodePartition, code)
}

func (ds *dynamodbStorage) DeleteClient(id string) error {
	return ds.delete(clientPartition, id)
}

func (ds *dynamodbStorage) DeleteRefresh(id string) error {
	return ds.delete(refreshTokenPartition, id)
}

func (ds *dynamodbStorage) DeletePassword(email string) error {
	return ds.delete(passwordPartition, strings.ToLower(email))
}

func (ds *dynamodbStorage) DeleteOfflineSessions(userID string, connID string) error {
	id := fmt.Sprintf("%s/%s", userID, connID)

	return ds.delete(offlineSessionPartition, id)
}

func (ds *dynamodbStorage) DeleteConnector(id string) error {
	return ds.delete(connectorPartition, id)
}

func (ds *dynamodbStorage) UpdateClient(id string, updater func(old storage.Client) (storage.Client, error)) error {
	var (
		err    error
		client storage.Client
	)

	ds.tx(func() {
		var cl Client

		err = ds.getByID(clientPartition, id, &cl)
		if err != nil {
			return
		}

		if client, err = updater(toStorageClient(cl)); err == nil {
			err = ds.update(clientPartition, fromStorageClient(client))
		}
	})

	return err
}

func (ds *dynamodbStorage) UpdateKeys(updater func(old storage.Keys) (storage.Keys, error)) error {
	var (
		err  error
		keys storage.Keys
	)

	ds.tx(func() {
		var k Keys

		firstUpdate := false

		err = ds.getByID(keysPartition, keysID, &k)
		if err != nil {
			if err != storage.ErrNotFound {
				return
			}

			firstUpdate = true
			k = Keys{}
		}

		keys, err = toStorageKeys(k)
		if err != nil {
			return
		}

		if keys, err = updater(keys); err == nil {
			if firstUpdate {
				err = ds.create(keysPartition, fromStorageKeys(keys))
			} else {
				err = ds.update(keysPartition, fromStorageKeys(keys))
			}
		}
	})

	return err
}

func (ds *dynamodbStorage) UpdateAuthRequest(id string, updater func(a storage.AuthRequest) (storage.AuthRequest, error)) error {
	var (
		err         error
		authRequest storage.AuthRequest
	)

	ds.tx(func() {
		var arw AuthRequest

		err = ds.getByID(authRequestPartition, id, &arw)
		if err != nil {
			return
		}

		if authRequest, err = updater(toStorageAuthRequest(arw)); err == nil {
			err = ds.update(authRequestPartition, fromStorageAuthRequest(authRequest))
		}
	})

	return err
}

func (ds *dynamodbStorage) UpdateRefreshToken(id string, updater func(r storage.RefreshToken) (storage.RefreshToken, error)) error {
	var (
		err          error
		refreshToken storage.RefreshToken
	)

	ds.tx(func() {
		var rt RefreshToken

		err = ds.getByID(refreshTokenPartition, id, &rt)
		if err != nil {
			return
		}

		if refreshToken, err = updater(toStorageRefreshToken(rt)); err == nil {
			err = ds.update(refreshTokenPartition, fromStorageRefreshToken(refreshToken))
		}
	})

	return err
}

func (ds *dynamodbStorage) UpdateDeviceToken(deviceCode string, updater func(t storage.DeviceToken) (storage.DeviceToken, error)) error {
	var (
		err         error
		deviceToken storage.DeviceToken
	)

	ds.tx(func() {
		var dt DeviceToken

		err = ds.getByID(refreshTokenPartition, deviceCode, &dt)
		if err != nil {
			return
		}

		if deviceToken, err = updater(toStorageDeviceToken(dt)); err == nil {
			err = ds.update(deviceTokenPartition, fromStorageDeviceToken(deviceToken))
		}
	})

	return err
}

func (ds *dynamodbStorage) UpdatePassword(email string, updater func(p storage.Password) (storage.Password, error)) error {
	var (
		err      error
		password storage.Password
	)

	ds.tx(func() {
		var pw Password

		err = ds.getByID(passwordPartition, strings.ToLower(email), &pw)
		if err != nil {
			return
		}

		if password, err = updater(toStoragePassword(pw)); err == nil {
			err = ds.update(passwordPartition, fromStoragePassword(password))
		}
	})

	return err
}

func (ds *dynamodbStorage) UpdateOfflineSessions(userID string, connID string, updater func(s storage.OfflineSessions) (storage.OfflineSessions, error)) error {
	var (
		err            error
		offlineSession storage.OfflineSessions
	)

	id := fmt.Sprintf("%s/%s", userID, connID)

	ds.tx(func() {
		var osw OfflineSessions

		err = ds.getByID(offlineSessionPartition, id, &osw)
		if err != nil {
			return
		}

		if offlineSession, err = updater(toStorageOfflineSessions(osw)); err == nil {
			err = ds.update(offlineSessionPartition, fromStorageOfflineSessions(offlineSession))
		}
	})

	return err
}

func (ds *dynamodbStorage) UpdateConnector(id string, updater func(c storage.Connector) (storage.Connector, error)) error {
	var (
		err       error
		connector storage.Connector
	)

	ds.tx(func() {
		var ct Connector

		err = ds.getByID(connectorPartition, id, &ct)
		if err != nil {
			return
		}

		if connector, err = updater(toStorageConnector(ct)); err == nil {
			err = ds.update(connectorPartition, fromStorageConnector(connector))
		}
	})

	return err
}

func (ds *dynamodbStorage) GarbageCollect(now time.Time) (storage.GCResult, error) {
	ds.logger.Warnf("placeholder GC at %v", now)
	return storage.GCResult{}, nil
}

func (ds *dynamodbStorage) tx(f func()) {
	f()
}

// creates records in DynamoDB with a condition which checks for existing unexpired records
func (ds *dynamodbStorage) create(partition string, rec interface{}) error {
	ds.logger.Debugf("create record in %s with data: %+v", partition, rec)

	checkExpires := dexp.And(
		dexp.AttributeNotExists(dexp.Name("expiry")),
		dexp.Name("expiry").LessThan(dexp.Value(time.Now().Unix())),
	)

	// if the record does NOT exists and or IS expired
	checkExists := dexp.And(
		dexp.AttributeNotExists(dexp.Name("pk")),
		dexp.AttributeNotExists(dexp.Name("sk")),
	)

	cond := dexp.Or(checkExists, checkExpires)

	err := ds.updateWithCondition(partition, rec, cond)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				return storage.ErrAlreadyExists
			}
		}

		return errors.Wrap(err, "failed to create condition")
	}

	return nil
}

func (ds *dynamodbStorage) update(partition string, rec interface{}) error {
	ds.logger.Debugf("update record in %s with data: %+v", partition, rec)

	// if the record exists and is NOT expired
	checkExists := dexp.And(
		dexp.AttributeExists(dexp.Name("pk")),
		dexp.AttributeExists(dexp.Name("sk")),
	)

	checkExpires := dexp.Or(
		dexp.AttributeNotExists(dexp.Name("expires")),
		dexp.Name("expires").GreaterThan(dexp.Value(time.Now().Unix())),
	)

	cond := dexp.And(checkExists, checkExpires)

	err := ds.updateWithCondition(partition, rec, cond)
	if err != nil {
		ds.logger.Errorf("updateWithCondition failed: %v", err)
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				return storage.ErrNotFound
			}
		}

		return errors.Wrap(err, "failed to update record")
	}

	return nil
}

func (ds *dynamodbStorage) getByID(partition string, id string, rec interface{}) error {
	ds.logger.Debugf("getByID record from %s with id: %s", partition, id)

	res, err := ds.ddb.GetItem(&dynamodb.GetItemInput{
		TableName:      aws.String(ds.tableName),
		ConsistentRead: aws.Bool(true),
		Key:            buildKeys(partition, id),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeResourceNotFoundException:
				return storage.ErrNotFound
			}
		}
		return errors.Wrapf(err, "failed to get record by id: %s", id)
	}

	if res.Item == nil {
		return storage.ErrNotFound
	}

	err = dynamodbattribute.UnmarshalMap(res.Item, rec)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshall record")
	}

	return nil
}

func (ds *dynamodbStorage) delete(partition string, id string) error {
	ds.logger.Debugf("delete record from %s with id: %s", partition, id)

	// if the record exists and is NOT expired
	checkExists := dexp.And(
		dexp.AttributeExists(dexp.Name("pk")),
		dexp.AttributeExists(dexp.Name("sk")),
	)

	checkExpires := dexp.Or(
		dexp.AttributeNotExists(dexp.Name("expires")),
		dexp.Name("expires").GreaterThan(dexp.Value(time.Now().Unix())),
	)

	cond := dexp.And(checkExists, checkExpires)

	expr, err := dexp.NewBuilder().WithCondition(cond).Build()
	if err != nil {
		return errors.Wrap(err, "failed to build dynamodb expression")
	}

	res, err := ds.ddb.DeleteItem(&dynamodb.DeleteItemInput{
		TableName:                 aws.String(ds.tableName),
		ReturnConsumedCapacity:    aws.String(dynamodb.ReturnConsumedCapacityTotal),
		Key:                       buildKeys(partition, id),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				return storage.ErrNotFound
			case dynamodb.ErrCodeResourceNotFoundException:
				return storage.ErrNotFound
			}
		}
		return errors.Wrapf(err, "failed to delete %s by id: %s", partition, id)
	}

	ds.logger.Debugf("delete %s / %s returned capacity: %f", partition, id, aws.Float64Value(res.ConsumedCapacity.CapacityUnits))

	return nil
}

func (ds *dynamodbStorage) list(partition string) ([]map[string]*dynamodb.AttributeValue, error) {
	ds.logger.Debugf("list records in %s", partition)

	res, err := ds.ddb.Query(&dynamodb.QueryInput{
		TableName:              aws.String(ds.tableName),
		ConsistentRead:         aws.Bool(true),
		KeyConditionExpression: aws.String("#partition = :partition"),
		ExpressionAttributeNames: map[string]*string{
			"#partition": aws.String("pk"),
		},
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":partition": {S: aws.String(partition)},
		},
	})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (ds *dynamodbStorage) updateWithCondition(partition string, rec interface{}, cond dexp.ConditionBuilder) error {
	item, err := dynamodbattribute.MarshalMap(rec)
	if err != nil {
		return errors.Wrap(err, "failed to marshall record")
	}

	// rewrite keys and expiry in item
	err = transformItem(partition, item)
	if err != nil {
		return errors.Wrap(err, "failed to transform record to dynamodb item")
	}

	expr, err := dexp.NewBuilder().WithCondition(cond).Build()
	if err != nil {
		return errors.Wrap(err, "failed to build dynamodb expression")
	}

	params := &dynamodb.PutItemInput{
		Item:                      item,
		ReturnConsumedCapacity:    aws.String(dynamodb.ReturnConsumedCapacityTotal),
		TableName:                 aws.String(ds.tableName),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}

	ds.logger.Debugf("update: %+v", params)

	res, err := ds.ddb.PutItem(params)
	if err != nil {
		return err
	}

	ds.logger.Debugf("update with condition %s returned capacity: %f", partition, aws.Float64Value(res.ConsumedCapacity.CapacityUnits))

	return nil
}

func (ds *dynamodbStorage) createTable(billingMode string, throughput *dynamodb.ProvisionedThroughput) error {
	_, err := ds.ddb.CreateTable(&dynamodb.CreateTableInput{
		TableName: aws.String(ds.tableName),
		KeySchema: []*dynamodb.KeySchemaElement{
			{AttributeName: aws.String("pk"), KeyType: aws.String(dynamodb.KeyTypeHash)},
			{AttributeName: aws.String("sk"), KeyType: aws.String(dynamodb.KeyTypeRange)},
		},
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{AttributeName: aws.String("pk"), AttributeType: aws.String(dynamodb.ScalarAttributeTypeS)},
			{AttributeName: aws.String("sk"), AttributeType: aws.String(dynamodb.ScalarAttributeTypeS)},
		},
		// use the supplied billing mode and throughput
		BillingMode:           aws.String(billingMode),
		ProvisionedThroughput: throughput,
		// always encrypt our table
		SSESpecification: &dynamodb.SSESpecification{
			Enabled: aws.Bool(true),
			SSEType: aws.String(dynamodb.SSETypeAes256),
		},
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeResourceInUseException:
				return nil
			}
		}
		return err
	}

	err = ds.ddb.WaitUntilTableExists(&dynamodb.DescribeTableInput{
		TableName: aws.String(ds.tableName),
	})
	if err != nil {
		return err
	}

	_, err = ds.ddb.UpdateTimeToLive(&dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(ds.tableName),
		TimeToLiveSpecification: &dynamodb.TimeToLiveSpecification{
			AttributeName: aws.String("expires"),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func (ds *dynamodbStorage) dropTable() error {
	_, err := ds.ddb.DeleteTable(&dynamodb.DeleteTableInput{TableName: aws.String(ds.tableName)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeResourceNotFoundException:
				return nil
			}
		}
		return err
	}

	err = ds.ddb.WaitUntilTableNotExists(&dynamodb.DescribeTableInput{
		TableName: aws.String(ds.tableName),
	})
	if err != nil {
		return err
	}

	return nil
}

func transformItem(partition string, item map[string]*dynamodb.AttributeValue) error {
	// assign the partition key
	item["pk"] = &dynamodb.AttributeValue{S: aws.String(partition)}

	//// rewrite the identifier for the record
	//val, ok := item["id"]
	//if !ok {
	//	return errors.New("failed to locate id for rewrite")
	//}
	//
	//// delete(item, "id")
	//item["sk"] = val

	return nil
}

func buildKeys(partition, key string) map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"pk": {S: aws.String(partition)},
		"sk": {S: aws.String(key)},
	}
}
