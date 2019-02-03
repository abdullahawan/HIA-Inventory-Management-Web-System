const AWS = require('aws-sdk');
AWS.config.update({region: 'us-east-1'});

docClient = new AWS.DynamoDB.DocumentClient();

const tableName = 'products';

module.exports = class Product {
  constructor(id, title, imageUrl, cost, price, fairlane_quantity, detroit_quantity) {
    this.id = id;
    this.title = title;
    this.imageUrl = imageUrl;
    this.cost = cost;
    this.price = price;
    this.fairlane_quantity = fairlane_quantity;
    this.detroit_quantity = detroit_quantity;
  }

  save() {

  }

  static fetchAll() {
    return docClient.scan({
      TableName: tableName
    }, (err, data) => {
      if (err) {
        return console.log(err.stack);
      } else {
        return data
      }
    }).promise();
  }

  static fetchProduct(prodId, timeStamp) {
    return docClient.get({
        TableName: tableName,
        Key: {
          "product_id": prodId,
          "timestamp": timeStamp
        }
      }, (err, data) => {
        if (err) {
          return console.log(err.stack);
        } else {
          return data;
        }
      }).promise();
  }

  static findById(prodId, timeStamp) {
    return docClient.get({
      TableName: tableName,
      Key: {
        "product_id": prodId,
        "timestamp": timeStamp
      }
    }, (err, data) => {
      if (err) return err;
      else {
        return data;
      }
    }).promise();
  }

  static deleteProduct(prodId, timeStamp) {
    return docClient.delete({
      TableName: tableName,
      Key: {
        "product_id": prodId,
        "timestamp": timeStamp
      }
    }, (err, data) => {
      if (err) {
        return console.log(err);
      } else {
        return data
      }
    }).promise();
  }

};
