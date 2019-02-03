const Product = require('../models/product');

const uuidv4 = require('uuid/v4');
const moment = require('moment');
const async = require('async');
const _ = require('underscore');
const AWS = require('aws-sdk');
AWS.config.update({region: 'us-east-1'});

const docClient = new AWS.DynamoDB.DocumentClient();
const tableName = 'products';

exports.getAddProduct = function (req, res) {
  res.render('admin/edit-product', {
    pageTitle: 'Add Product',
    path: '/admin/add-product',
    editing: false,
  });
};

exports.postAddProduct = function (req, res) {
  let product_id = uuidv4();
  let timeStamp = moment().unix();
  let title = req.body.title;
  let imageUrl = req.body.imageUrl;
  let brand = req.body.brand;
  let cost = req.body.cost;
  let price = req.body.price;
  let user = req.user;
  let fairlane_quantity = req.body.fairlane_quantity;
  let detroit_quantity = req.body.detroit_quantity;

  docClient.put({
    TableName: tableName,
    Item: {
      "product_id": product_id,
      "timestamp": timeStamp,
      "title": title,
      "image_url": imageUrl,
      "brand": brand,
      "cost": cost,
      "price": price,
      "added_by": user.email,
      "fairlane_quantity": fairlane_quantity,
      "detroit_quantity": detroit_quantity
    }
  }, (err, data) =>{
    if (err) {
      console.log(err.stack);
      return res.redirect('/');
    } else {
      return res.redirect('/');
    }
  });
};


exports.getEditProduct = function (req, res) {
  const editMode = req.query.edit;
  const editModeBoolean = (editMode === 'true');
  if (!editModeBoolean) {
    return res.redirect('/');
  }
  let prodId = req.params.productId;
  let productIdQuery = req.query.pId;
  let timeStampQuery = parseInt(req.query.ts);
  docClient.get({
    TableName: tableName,
    Key: {
      "product_id": productIdQuery,
      "timestamp": timeStampQuery
    }
  }, (err, data) => {
    if (err) {
      console.log(err.stack);
      res.redirect('/admin/products');
    } else {
      res.render('admin/edit-product', {
        pageTitle: 'Edit Product',
        path: '/admin/edit-product',
        editing: editModeBoolean,
        product: data.Item
      });
    }
  });
};

exports.postEditProduct = function (req, res) {
  let product_id = req.body.productId;
  let timeStamp = parseInt(req.body.timeStamp);
  let title = req.body.title;
  let imageUrl = req.body.imageUrl;
  let brand = req.body.brand;
  let cost = req.body.cost;
  let price = req.body.price;
  let fairlane_quantity = req.body.fairlane_quantity;
  let detroit_quantity = req.body.detroit_quantity;
  let userEmail = req.user.email;

  docClient.update({
    TableName: tableName,
    Key: {
      "product_id": product_id,
      "timestamp": timeStamp
    },
    UpdateExpression: `set title = :title,
      image_url = :imageUrl,
      brand = :brand,
      price = :price,
      cost = :cost,
      fairlane_quantity = :fq,
      detroit_quantity = :dq,
      #leb = :leb`,
    ExpressionAttributeNames: {
      '#leb': 'last_edited_by'
    },
    ExpressionAttributeValues: {
      ':title': title,
      ':imageUrl': imageUrl,
      ':brand': brand,
      ':cost': cost,
      ':price': price,
      ':fq': fairlane_quantity,
      ':dq': detroit_quantity,
      ':leb': userEmail
    }
  }, (err, data) =>{
    if (err) {
      console.log(err.stack);
      return res.redirect('/admin/products');
    } else {
      return res.redirect('/admin/products');
    }
  });
};

exports.getProducts = (req, res) => {
  Product.fetchAll()
    .then((products) => {
      res.render('admin/products', {
        prods: products.Items,
        pageTitle: 'Shop',
        path: '/admin/products'
      });
    })
    .catch((err) => {
      console.log(err);
      res.redirect('/admin/products');
    });
};

exports.postDeleteProduct = (req, res) => {
  let prodId = req.body.productId;
  let timeStamp = parseInt(req.body.timeStamp);

  Product.deleteProduct(prodId, timeStamp)
    .then(() => {
      res.redirect('products');
    })
    .catch((err) => {
      console.log(err);
      res.redirect('products');
    });
};

exports.getUserCp = (req, res) => {
  res.render('admin/user-cp', {
    path: '/admin/user-cp',
    pageTitle: 'User Control Panel',
    user: req.user,
  })
}

exports.postUserCpStoreLocation = (req, res) => {
  let store_location = req.body.store_location;
  docClient.update({
    TableName: 'users',
    Key: {
      "email": req.user.email
    },
    UpdateExpression: 'set #store_location = :store_location',
    ExpressionAttributeNames: {
      '#store_location': 'store_location'
    },
    ExpressionAttributeValues: {
      ':store_location': store_location
    }
  }, (err, data) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect('/admin/user-cp');
    }
  });
}

exports.postUpdateUserInfo = (req, res) => {
  let user_name = req.body.user_name;
  docClient.update({
    TableName: 'users',
    Key: {
      "email": req.user.email
    },
    UpdateExpression: 'set #name = :name',
    ExpressionAttributeNames: {
      '#name': 'name'
    },
    ExpressionAttributeValues: {
      ':name': user_name
    }
  }, (err, data) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect('/admin/user-cp');
    }
  });
}
