const Product = require('../models/product');

const moment = require('moment');

const AWS = require('aws-sdk');
AWS.config.update({region:'us-east-1'});

const docClient = new AWS.DynamoDB.DocumentClient();


exports.getProducts = function (req, res) {
  Product.fetchAll()
    .then((products) => {
      res.render('shop/index', {
        prods: products.Items,
        pageTitle: 'Shop',
        path: '/products'
      });
    })
    .catch((err) => {
      console.log(err);
      res.redirect('/products');
    });
};

exports.getProduct = (req, res) => {
  let prodId = req.params.productId;
  let productIdQuery = req.query.pId;
  let timeStampQuery = parseInt(req.query.ts);

  Product.fetchProduct(productIdQuery, timeStampQuery)
    .then(product => {
      res.render('shop/product-detail', {
        pageTitle: product.Item.title,
        product: product.Item,
        path: '/products'
      });
    })
    .catch(err => {
      console.log(err);
      res.redirect('/products');
    });
};

exports.getIndex = (req, res) => {
  Product.fetchAll()
    .then((products) => {
      res.render('shop/index', {
        prods: products.Items,
        pageTitle: 'Shop',
        path: '/'
      });
    })
    .catch((err) => {
      console.log(err);
      res.redirect('/');
    });
};

exports.getCart = (req, res) => {
  req.user
    .getCart()
    .then(products => {
      if (products.items == 0) {
        res.render('shop/cart', {
          path: '/cart',
          pageTitle: 'Your Cart',
          products: products
        });
      } else {
        products = products.Items.map(p => {
          return {
            ...p,
            quantity: req.user.cart.items.find(i => {
              return i.product_id === p.product_id;
            }).quantity,
            productPrice: req.user.cart.items.find(i => {
              return i.product_id === p.product_id;
            }).productPrice
          }
        });
        let totalPrice = 0;

        products.forEach((product) => {
          let price = product.price * product.quantity;
          totalPrice += price;
        })

        res.render('shop/cart', {
          path: '/cart',
          pageTitle: 'Your Cart',
          products: products,
          totalPrice: totalPrice
        });
      }
    })
    .catch((err) => {
      res.redirect('/');
      console.log(err);
    });
};

exports.postCart = (req, res) => {
  let prodId = req.body.productId;
  let timeStamp = parseInt(req.body.timeStamp);
  Product.findById(prodId, timeStamp)
    .then((product) => {
      return req.user.addToCart(product.Item, req.user);
    })
    .then((result) => {
      res.redirect('/cart');
    })
    .catch((err) => {
      console.log(err);
    });
};

exports.postCartDeleteProduct = (req, res) => {
  let prodId = req.body.productId;
  req.user
    .deleteItemFromCart(prodId, req.user)
    .then(result => {
      res.redirect('/cart');
    })
    .catch(err => console.log(err));
};

exports.getOrders = (req, res) => {
  req.user.getOrders()
    .then((orders) => {
      orders = orders.Items
      res.render('shop/orders', {
        path: '/orders',
        pageTitle: 'Orders',
        orders: orders,
      });
    })
    .catch(err => console.log(err));
};

exports.getOrder = (req, res) => {
  let order_id = req.query.oId;
  let timeStamp = parseInt(req.query.ts);
  req.user.getOrder(order_id, timeStamp)
    .then(order => {
      order = order.Item;
      let date = new Date(order.timestamp * 1000).toLocaleString();
      res.render('admin/order-detail', {
        pageTitle: order.order_id,
        order: order,
        path: '/orders',
        date: date
      });
    })
    .catch(err => {
      console.log(err);
      res.redirect('/');
    })
}

exports.getCheckout = (req, res) => {
  req.user
    .getCart()
    .then(products => {
      if (products.items == 0) {
        res.render('shop/checkout', {
          path: '/checkout',
          pageTitle: 'Checkout',
        });
      } else {
        products = products.Items.map(p => {
          return {
            ...p,
            quantity: req.user.cart.items.find(i => {
              return i.product_id === p.product_id;
            }).quantity,
            productPrice: req.user.cart.items.find(i => {
              return i.product_id === p.product_id;
            }).productPrice
          }
        });
        let totalPrice = 0;

        products.forEach((product) => {
          let price = product.price * product.quantity;
          totalPrice += price;
        })

        res.render('shop/checkout', {
          path: '/checkout',
          pageTitle: 'Checkout',
          products: products,
          totalPrice: totalPrice,
        });
      }
    })
    .catch((err) => {
      res.redirect('/');
      console.log(err);
    });
};

exports.postOrder = (req, res) => {
  let orderTotal = req.body.orderTotal;
  let adjustedTotal = req.body.adjustedTotal;
  let checkoutNotes = req.body.checkoutNotes;
  let userInfo = req.user;

  req.user
    .addOrder(orderTotal, adjustedTotal, checkoutNotes, userInfo)
    .then(result => {
      res.redirect('/orders');
    })
    .catch(err => console.log(err));
};

exports.postUpdateAdjustedTotal = (req, res) => {
  let order_id = req.body.order_id;
  let timeStamp = parseInt(req.body.timeStamp);
  let adjustedTotal = req.body.adjustedPrice;

  docClient.update({
    TableName: 'orders',
    Key: {
      "order_id": order_id,
      "timestamp": timeStamp
    },
    UpdateExpression: 'set #adjustedTotal = :adjustedTotal',
    ExpressionAttributeNames: {
      '#adjustedTotal': 'is_order_adjusted'
    },
    ExpressionAttributeValues: {
      ':adjustedTotal': adjustedTotal
    }
  }, (err, data) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect('/orders');
    }
  });
}
