const AWS = require('aws-sdk');
const uuidv4 = require('uuid/v4');
const moment = require('moment');

AWS.config.update({region: 'us-east-1'});

const docClient = new AWS.DynamoDB.DocumentClient();

const tableName = 'users';


class User {
  constructor(name, email, password, resetToken, resetTokenExpiration, storeLocation, cart) {
    this.name = name;
    this.email = email;
    this.password = password;
    this.resetToken = resetToken;
    this.resetTokenExpiration = resetTokenExpiration;
    this.storeLocation = storeLocation;
    this.cart = cart;
  }

  save() {
    return docClient.put({
        TableName: tableName,
        Item: {
          "email": this.email,
          "password": this.password,
          "store_location": this.storeLocation
        }
      }, (err, data) => {
        if (err) {
          return console.log(err);
        } else {
          return data.Item;
        }
      }).promise();
  }

  getUser(email) {
    return docClient.get({
      TableName: 'users',
      Key: {
        "email": email
      }
    }, (err, data) => {
      if (err) return err;
      else return data;
    }).promise();
  }

  addToCart(product, user) {
    if (typeof(this.cart) === 'undefined' || this.cart.length == 0) {
      this.cart = {items: []}
    }
    let cartProductIndex = this.cart.items.findIndex(cp => {
      return cp.product_id === product.product_id;
    });
    let newQuantity = 1;
    let price = 0;

    let updatedCartItems = [...this.cart.items];

    if (cartProductIndex >= 0) {
      newQuantity = this.cart.items[cartProductIndex].quantity + 1;
      updatedCartItems[cartProductIndex].quantity = newQuantity;
      price = product.price * newQuantity;
      updatedCartItems[cartProductIndex].productPrice = price;
    } else {
      updatedCartItems.push({
        product_id: product.product_id,
        timestamp: product.timestamp,
        quantity: newQuantity,
        productPrice: product.price
      });
    }


    const updatedCart = {
      items: updatedCartItems
    }

    return docClient.update({
      TableName: tableName,
      Key: {
        "email": user.email
      },
      UpdateExpression: "set #cart = :cart",
      ConditionExpression: '#id = :id',
      ExpressionAttributeNames: {
        '#id': 'email',
        '#cart': 'cart'
      },
      ExpressionAttributeValues: {
        ':id': user.email,
        ':cart': updatedCart
      }
    }, (err, data) => {
      if (err) return err;
      else return data;
    }).promise();

  }

  getCart() {
    if (typeof(this.cart) === 'undefined' || this.cart.items == 0) {
      this.cart = {items: []};
      let promise = new Promise((resolve, reject) => {
        resolve(this.cart);
      });

      return promise;
    } else {
      let productIds = this.cart.items.map(i => {
        return i.product_id;
      });
      let productObject ={};
      let index = 0;

      productIds.forEach((value) => {
        index++;
        var productKey = ":pid"+index;
        productObject[productKey.toString()] = value;
      });

      return docClient.scan({
        TableName: 'products',
        FilterExpression: "product_id IN ("+Object.keys(productObject).toString()+ ")",
        ExpressionAttributeValues: productObject
      }, (err, data) => {
        if (err) return err;
        else  return data
      }).promise();
    }

  }

  deleteItemFromCart(prodId, user) {
    let updatedCartItems = this.cart.items.filter(item => {
      return item.product_id !== prodId;
    });

    return docClient.update({
      TableName: tableName,
      Key: {
        "email": user.email
      },
      UpdateExpression: "set #cart.#items = :cart",
      ConditionExpression: '#id = :id',
      ExpressionAttributeNames: {
        '#id': 'email',
        '#cart': 'cart',
        '#items': 'items'
      },
      ExpressionAttributeValues: {
        ':id': user.email,
        ':cart': updatedCartItems
      }
    }, (err, data) => {
      if (err) return err;
      else return data;
    }).promise();
  }

  addOrder(orderTotal, adjustedTotal, checkoutNotes, user) {
    let orderId = uuidv4();
    let timeStamp = moment().unix();

    return this.getCart().then((products) => {
      return products = products.Items.map(p => {
        return {
          ...p,
          quantity: this.cart.items.find(i => {
            return i.product_id === p.product_id;
          }).quantity,
          productPrice: this.cart.items.find(i => {
            return i.product_id === p.product_id;
          }).productPrice
        }
      });
    }).then((products) => {
      if (checkoutNotes.length == 0) {
        checkoutNotes = " ";
      }
      const item = {
        "order_id": orderId,
        "timestamp": timeStamp,
        "user": {
          "name": user.name,
          "email": user.email
        },
        "items": products,
        "order_total": orderTotal,
        "is_order_adjusted": adjustedTotal,
        "checkout_notes": checkoutNotes,
        "store_location": user.storeLocation
      }

      return docClient.put({
        TableName: 'orders',
        Item: item
      }, (err, data) => {
        if (err) return err;
        else {
          let updatedCart = [];
          docClient.update({
            TableName: tableName,
            Key: {
              "email": this.email
            },
            UpdateExpression: "set #cart.#items = :cart",
            ConditionExpression: '#id = :id',
            ExpressionAttributeNames: {
              '#id': 'email',
              '#cart': 'cart',
              '#items': 'items'
            },
            ExpressionAttributeValues: {
              ':id': this.email,
              ':cart': updatedCart
            }
          }, (err, data) => {
            if (err) return err;
            else return data;
          }).promise();
        }
      }).promise();
    })

  }

  getOrders() {
    return docClient.scan({
      TableName: 'orders',
    }, (err, data) => {
      if (err) return err;
      else return data;
    }).promise();
  }

  getOrder(order_id, timeStamp) {
    return docClient.get({
      TableName: 'orders',
      Key: {
        "timestamp": timeStamp,
        "order_id": order_id
      }
    }, (err, data) => {
      if (err) return err;
      else {
        return data;
      }
    }).promise();
  }

  static findById(email) {
    return docClient.get({
      TableName: tableName,
      Key: {
        "email": email
      }
    }, (err, data) => {
      if (err) return err;
      else {
        return data.Item;
      }
    }).promise();
  }

}

module.exports = User;
