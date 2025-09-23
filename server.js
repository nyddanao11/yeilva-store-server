const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto =require('crypto');
const cors = require('cors');
const knex = require('knex');
const cron = require('node-cron');
const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const axios = require('axios');
const { Readable } = require('stream');
const { GetObjectCommand } = require('@aws-sdk/client-s3');
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { fromEnv } = require("@aws-sdk/credential-provider-env");
const { S3 } = require('@aws-sdk/client-s3');
const multer = require('multer');
const multerS3 = require('multer-s3');
const storage = multer.memoryStorage(); // Use memory storage to get the buffer
const uploadMultiple= multer({ storage: storage }).fields([
  { name: 'installmentImage', maxCount: 1 }, // Field for ID image
  { name: 'selfie', maxCount: 1 }            // Field for selfie image
]);
const uploadLoan= multer({ storage: storage }).fields([
  { name: 'image', maxCount: 1 }, // Field for ID image
  { name: 'selfieimage', maxCount: 1 }            // Field for selfie image
]);
const upload = multer({ storage: storage });
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const checkAuthRouter = require('./Routes/checkAuth');
require('dotenv').config({ path: 'sendgrid.env' });
require('dotenv').config({ path: 'paymongo.env' });
require('dotenv').config({ path: 'tokensecret.env' });
require('dotenv').config({ path: 's3.env' });
require('dotenv').config();
const { Sequelize, DataTypes, Op } = require('sequelize');


const sequelize = new Sequelize(
  `postgres://${process.env.POSTGRES_USER}:${process.env.POSTGRES_PASSWORD}@${process.env.RAILWAY_TCP_PROXY_DOMAIN}:${process.env.RAILWAY_TCP_PROXY_PORT}/${process.env.POSTGRES_DB}`
);

const db = knex({
  client: 'pg',
  connection: {
    host: process.env.RAILWAY_TCP_PROXY_DOMAIN,
    port: process.env.RAILWAY_TCP_PROXY_PORT,
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    database: process.env.POSTGRES_DB,
  },
});

const pool = new Pool({
   host: process.env.RAILWAY_TCP_PROXY_DOMAIN,
    port: process.env.RAILWAY_TCP_PROXY_PORT,
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    database: process.env.POSTGRES_DB,
  
});

const AccessKey = process.env.ACCESS_KEY;
const SecretKey = process.env.SECRET_ACCESS_KEY;
const bucketRegion = process.env.BUCKET_REGION;
const BucketName = process.env.BUCKET_NAME;



const s3 = new S3Client({
  region: bucketRegion,
  credentials: {
    accessKeyId: AccessKey,
    secretAccessKey: SecretKey,
  },
});



const app = express();
const router = express.Router();
app.use(express.json());


// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// app.use(cors());


app.use(cors({ 
  origin: 'https://yeilvastore.com', 
  credentials: true,
}));

app.use(cookieParser());


app.use('/api/check-auth', checkAuthRouter);


// const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
// sgMail.setApiKey(SENDGRID_API_KEY);

const transporter = nodemailer.createTransport({
  host: 'smtp.yeilvastore.com',
  port: 465, // or 465 if using SSL/587 less secure
  secure: true, // true for port 465/false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false // optional, helps with self-signed certs
  }
});

// Routes
app.get('/', (req, res) => {
  res.send('This is working');
});


app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userData = await db('users')
      .select('email', 'password', 'verified', 'status', 'login_attempts', 'last_login_attempt', 'lockout_until')
      .where('email', '=', email)
      .first();

    // console.log('Retrieved userData:', userData);

    if (!userData) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (!userData.verified) {
      return res.status(400).json({ error: 'Email not verified. Please check your email for verification instructions.' });
    }

    if (userData.status !== 'active') {
      return res.status(400).json({ error: 'Account deactivated' });
    }

    const currentDateTime = new Date();
    const loginAttempts = userData.login_attempts + 1;

    const isValid = bcrypt.compareSync(password, userData.password);

    let lockoutUntil = userData.lockout_until;
    
    // Check if the lockout period is still active
    if (lockoutUntil && currentDateTime < new Date(lockoutUntil)) {
      return res.status(400).json({
        error: `Account locked. Please try again after ${Math.ceil((new Date(lockoutUntil) - currentDateTime) / (60 * 1000))} minutes.`,
      });
    }

    if (isValid) {
      // Reset login attempts on successful login
      await db('users').where('email', '=', email).update({ login_attempts: 0, last_login_attempt: currentDateTime, lockout_until: null });

      // Return success
      return res.json({ status: 'success', email: email });
    } else {
      // If less than three attempts, update the login attempts and last login attempt timestamp
      if (loginAttempts < 3) {
        await db('users').where('email', '=', email).update({
          login_attempts: loginAttempts,
          last_login_attempt: currentDateTime,
        });
      } else {
        // If the third attempt, set lockout
        const lockoutTime = 15 * 60 * 1000; // 15 minutes in milliseconds
        lockoutUntil = new Date(currentDateTime.getTime() + lockoutTime);

        await db('users').where('email', '=', email).update({
          login_attempts: 0, // Reset login attempts after lockout
          last_login_attempt: currentDateTime,
          lockout_until: lockoutUntil,
        });

        return res.status(400).json({
          error: `Invalid credentials. Login attempt ${loginAttempts}/3. Account locked for ${Math.ceil(lockoutTime / (60 * 1000))} minutes.`,
        });
      }

      // Provide information about login attempts
      return res.status(400).json({
        error: `Invalid credentials. Login attempt ${loginAttempts}/3.`,
      });
    }
  } catch (err) {
    console.error('Error during login:', err);
    return res.status(500).json({ error: 'An error occurred during login' });
  }
});



app.get('/api/userstatus', async (req, res) => {
  try {
    const userStatusEmail = req.query.email;
    console.log('Received request for user email:', userStatusEmail); // Add this line for debugging

   const query = 'SELECT firstname, lastname, email, status, TO_CHAR(timestamp, \'YYYY-MM-DD\') AS joineddate FROM users WHERE email = $1';

    const result = await pool.query(query, [userStatusEmail]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }


    const user = result.rows[0];
    console.log('User data sent to client:', user);
    return res.json(user);

   
  } catch (error) {
    console.error('Error executing SQL query:', error); // Log the SQL query error
    return res.status(500).json({ error: 'Internal server error' });
  }
});



app.post('/api/user/updateStatus', async (req, res) => {
  const { email, status } = req.body;

  try {
    // Perform database update for status
    await pool.query(
      'UPDATE users SET status = $1 WHERE email = $2',
      [status, email]
    );

    res.json({ success: true, message: 'Status updated successfully' });
  } catch (error) {
    console.error('Error updating status:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});



function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

app.post('/register', async (req, res) => {
  const { email, firstname, lastname, password } = req.body;

  // Input validation
  if (!email || !firstname || !lastname || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const existingUser = await db('users').where('email', '=', email).first();
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const token = generateToken();

    await db('users').insert({
      firstname,
      lastname,
      email,
      password: hash,
      token,
      verified: false,
      status: 'active',
      timestamp: new Date()
    });

    // Send a successful response to the client immediately
    res.status(201).json({ message: 'User registered successfully. A verification email has been sent.' });

    // Send the email after the response to the client
  const verificationLink = `https://yeilvastore.com/confirm?token=${token}`;

const mailOptions = {
    from: '"YeilvaStore" <noreply@yeilvastore.com>',
    to: email,
    subject: 'Confirm Your Email Address',
    html: `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>YeilvaStore Email Verification</title>
            <style>
                body {
                    margin: 0;
                    padding: 0;
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    color: #333333;
                }
                .container {
                    max-width: 600px;
                    margin: 20px auto;
                    background-color: #ffffff;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    border-top: 4px solid #007bff;
                }
                .header {
                    text-align: center;
                    padding-bottom: 20px;
                    border-bottom: 1px solid #eaeaee;
                }
                .header img {
                    max-width: 150px;
                    height: auto;
                }
                .content {
                    padding: 20px 0;
                    line-height: 1.6;
                    text-align: center;
                }
                .content p {
                    font-size: 16px;
                    margin: 0 0 15px;
                }
                .button-container {
                    text-align: center;
                    padding: 20px 0;
                }
                .button {
                    display: inline-block;
                    padding: 12px 24px;
                    font-size: 16px;
                    color: #ffffff;
                    background-color: #007bff;
                    border-radius: 5px;
                    text-decoration: none;
                    font-weight: bold;
                }
                .footer {
                    text-align: center;
                    padding-top: 20px;
                    border-top: 1px solid #eaeaee;
                    font-size: 12px;
                    color: #777777;
                }
                .footer a {
                    color: #007bff;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <a href="https://yeilvastore.com" target="_blank" rel="noopener noreferrer">
                        <img src="https://yeilvastore.com/logo.png" alt="YeilvaStore Logo">
                    </a>
                </div>
                <div class="content">
                    <p><strong>Hi ${firstname},</strong></p>
                    <p>Thanks for signing up for an account with YeilvaStore!</p>
                    <p>To complete your registration, please click the button below to verify your email address:</p>
                    <div class="button-container">
                        <a href="${verificationLink}" class="button">Verify Email Address</a>
                    </div>
                    <p>If the button doesn't work, you can also copy and paste the following link into your browser:</p>
                    <p><a href="${verificationLink}" style="font-size: 12px; color: #007bff;">${verificationLink}</a></p>
                </div>
                <div class="footer">
                    <p>If you have any questions, reply to this email.</p>
                    <p>&copy; ${new Date().getFullYear()} YeilvaStore. All rights reserved.</p>
                    <p>
                        <a href="https://yeilvastore.com" target="_blank" rel="noopener noreferrer">Visit Our Website</a>
                    </p>
                </div>
            </div>
        </body>
        </html>
    `
};

    // Use a try-catch block for sending the email, but don't hold up the API response.
    try {
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent:', info.response);
    } catch (emailErr) {
      console.error('Error sending verification email:', emailErr);
    }

  } catch (dbErr) {
    console.error('Error during registration:', dbErr);
    res.status(500).json({ error: 'An error occurred during registration.' });
  }
});

// Endpoint for handling email confirmation
app.get('/confirm', async (req, res) => {
  const { token } = req.query;

  try {
    // Check if the token exists and is not expired in the PostgreSQL database
    const result = await db('users')
      .where({ token: token })
      .andWhere('timestamp', '>', new Date(Date.now() - (24 * 60 * 60 * 1000))) // Check tokens valid for 24 hours

    if (result.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // Mark the user's email as verified in the PostgreSQL database
    const email = result[0].email;
    await db('users')
      .where({ email: email })
      .update({ verified: true });

    // Optionally, you can delete the token from the database to prevent reuse
      const deleteResult = await pool.query(
      'UPDATE users SET token = NULL WHERE email = $1',
      [result[0].email]  // Use result[0].email instead of result.rows[0].email
    );


    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Error during email confirmation', error);
    res.status(500).json('An error occurred during email confirmation');
  }
});


const cleanNumericValue = (value) => {
  // Remove any non-numeric characters except decimal points
  return parseFloat(value.replace(/[^\d.-]/g, ''));
};

app.post('/checkout', async (req, res) => {
  const {
    firstname,
    lastname, 
    email,
     // Destructure using frontend names and assign to backend names
        streetAddress: address,     // Frontend's 'streetAddress' becomes backend's 'address'
        stateProvince: province,    // Frontend's 'stateProvince' becomes backend's 'province'
        phoneNumber: phone,         // Frontend's 'phoneNumber' becomes backend's 'phone'
        city,                       // Add city if you want to store it
        postalCode,                 // Add postalCode if you want to store it
        fullName,                   // Add fullName if you want to store it
        apartmentSuite,             // Add apartmentSuite if you want to store it
    name,
    quantity,
    total,
    paymentOption, 
    productNames,
    productPrice,
    productUrl,
    productWeight,
  } = req.body;
// console.log('CheckoutData', req.body);
  try {
       const cleanTotal = cleanNumericValue(total); // Clean the total value
    // Start a database transaction
    await db.transaction(async (trx) => {
      // Generate the order number
      const orderNumber = generateOrderNumber();
      const estimatedDate = new Date();
     estimatedDate.setDate(estimatedDate.getDate() + 8); // Add 9 days to the current date
  
  const formattedDeliveryDate = estimatedDate.toDateString(); // Convert to a readable date format

      // Insert data into the 'checkout' table, including the order number and new fields
      const insertedOrder = await trx('checkout')
        .insert({
          firstname, 
          lastname, 
          email,
          address,    // Now correctly mapped from streetAddress
          province,   // Now correctly mapped from stateProvince
          phone,      // Now correctly mapped from phoneNumber
          checkout_date: new Date(),
          name,
          quantity,
          total: cleanTotal,  // Insert cleaned total
          order_number: orderNumber,
          payment_option: paymentOption,
          productname: productNames,
          deliverydate: formattedDeliveryDate,
          price: productPrice,
          url: productUrl,
          weight: productWeight,
        })
        .returning('*');

      // Send a success response with the inserted data
      res.json({ success: true, checkoutData: insertedOrder });


        // Send an email with the checkout information to the customer
        const checkoutInfoEmailToCustomer = {
          to: email,
         from: '"YeilvaStore" <noreply@yeilvastore.com>',
          subject: 'Checkout Information',
         html: `
    <html>
      <body>
        <div style="max-width: 600px; margin: auto; font-family: Arial, sans-serif; padding: 20px;">
          <h1 style="text-align: center;">Thank You for Your Order!</h1>

          <p>Dear ${firstname} ${lastname},</p>
          
          <p>We wanted to express our heartfelt thanks for choosing YeilvaSTORE for your recent purchase. Your order # ${orderNumber} has been received and is now being processed.</p>

          <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Order Details</h3>

          <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
            <p><strong>Product:</strong> ${name}</p>
            <p><strong>Total Amount:</strong> ${total}</p>
            <p><strong>Payment Method:</strong> ${paymentOption}</p>
          </div>

          <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Shipping Address</h3>

          <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
           <p><strong>Full name:</strong> ${fullName}</p>
            <p><strong>Address:</strong> ${address}</p>
           <p><strong>City:</strong> ${city}</p>
            <p><strong>Province:</strong> ${province}</p>
           <p><strong>Postal Code:</strong> ${postalCode}</p>
          <p><strong>Apartment:</strong> ${apartmentSuite}</p>
            <p><strong>Phone:</strong> ${phone}</p>
          </div>

          <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at [yeilvastore@gmail.com] or [09497042268]. We're here to help!</p>

          <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>

          <p>Best regards,</p>
         <p><a href="https://yeilva-store.up.railway.app" target="_blank" rel="noopener noreferrer">YeilvaStore</a></p>
        </div>
      </body>
    </html>
          `,
        }; 

       
      // Send an email with the checkout information to the admin
const checkoutInfoEmailToAdmin = {
  to: 'bonz.ba50@gmail.com',
  from: 'yeilvastore@gmail.com',
  subject: 'New Checkout Information',
  html: `
    <html>
      <body>
        <div style="max-width: 600px; margin: auto; font-family: Arial, sans-serif; padding: 20px;">
          <h1 style="text-align: center;">Thank You for Your Order!</h1>

          <p>Dear ${firstname} ${lastname},</p>
          
          <p>We wanted to express our heartfelt thanks for choosing YeilvaSTORE for your recent purchase. Your order # ${orderNumber} has been received and is now being processed.</p>

          <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Order Details</h3>

          <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
            <p><strong>Product:</strong> ${name}</p>
             <p>Email Address: ${email}</p>
            <p><strong>Total Amount:</strong> ${total}</p>
            <p><strong>Payment Method:</strong> ${paymentOption}</p>
          </div>

          <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Shipping Address</h3>

          <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
               <p><strong>Full name:</strong> ${fullName}</p>
            <p><strong>Address:</strong> ${address}</p>
           <p><strong>City:</strong> ${city}</p>
            <p><strong>Province:</strong> ${province}</p>
           <p><strong>Postal Code:</strong> ${postalCode}</p>
          <p><strong>Apartment:</strong> ${apartmentSuite}</p>
            <p><strong>Phone:</strong> ${phone}</p>
          </div>

          <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at [yeilvastore@gmail.com] or [09497042268]. We're here to help!</p>

          <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>

          <p>Best regards,</p>
         <p><a href="https://yeilva-store.up.railway.app" target="_blank" rel="noopener noreferrer">YeilvaStore</a></p>
        </div>
      </body>
    </html>
  `,
};


        try {
  // Send checkout info email to customer
  await transporter.sendMail(checkoutInfoEmailToCustomer);
  // Send checkout info email to admin
  await transporter.sendMail(checkoutInfoEmailToAdmin);
  console.log('Checkout information emails sent successfully');
} catch (error) {
  console.error('Error sending emails:', error);
  // Handle email sending errors
}

      console.log('Checkout information emails sent successfully');
    }); // Close the try block here
  } catch (error) {
    console.error('Error during checkout:', error);
    res.status(500).json('An error occurred during checkout');
  }
});

// Generate an order number
function generateOrderNumber() {
  const timestamp = new Date().getTime(); // Current timestamp
  const randomPart = Math.floor(Math.random() * 1000); // Random number (adjust as needed)
  const orderNumber = `${timestamp}-${randomPart}`;
  return orderNumber;
}

// Example route to create a new order
app.post('/create-order', async (req, res) => {
  try {
    // Generate the order number
    const orderNumber = generateOrderNumber();

    // Insert the order into the database (replace 'orders' with your table name)
    await pool.query('INSERT INTO checkout (order_number, ...other_fields) VALUES ($1, ...other_values)', [orderNumber, ...other_params]);

    // Respond with the generated order number
    res.status(201).json({ orderNumber });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'An error occurred while creating the order' });
  }
});


app.get('/api/orderdata', async (req, res) => {
  try {
    const userEmail = req.query.email;

    const query = 'SELECT order_number, orderstatus, deliverydate FROM checkout WHERE email = $1 AND orderstatus::INTEGER < 4 ORDER BY orderstatus::INTEGER DESC';
    const result = await pool.query(query, [userEmail]);

    // console.log('orderdata', result.rows);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No orders found' });
    }

    return res.json(result.rows); // Return array of orders
  } catch (error) {
    console.error('Error executing SQL query:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Update order status and delivery date
app.put('/api/updateOrder', async (req, res) => {
    const { orderId, orderstatus, deliverydate } = req.body; // Destructure values from the request body
    // console.log('updateorder', req.body);

    try {
        const result = await pool.query(
            'UPDATE checkout SET orderstatus = $1, deliverydate = $2 WHERE order_number = $3', // Correct column name in WHERE clause
            [orderstatus, deliverydate, orderId] // Pass orderId directly as the parameter
        );

        res.status(200).json({ message: 'Order updated successfully' });
    } catch (error) {
        console.error('Error updating order:', error);
        res.status(500).json({ message: 'Error updating order' });
    }
});


app.put('/api/updateProductDetails', async (req, res) => {
    const { featured, bestselling, recommended, youmaylike, discount, stock, id} = req.body; // Destructure values from the request body
    // console.log('updateDiscount', req.body);

    if (!id) {
        return res.status(400).json({ message: "Product ID is required." });
    }

    try {
        const result = await pool.query(
            'UPDATE products SET featured = $1, bestselling = $2, recommended = $3, youmaylike = $4, discount = $5, stock =$6 WHERE id = $7',
            [featured, bestselling, recommended, youmaylike, discount, stock, id]
        );
        res.status(200).json({ message: 'Product details updated successfully' });
    } catch (error) {
        console.error('Database update error:', error);
        res.status(500).json({ message: 'Error updating product details', error: error.message });
    }
});


app.get('/api/userorderdata', async (req, res) => {
  try {
    const userEmail = req.query.email;
    // console.log('Received request for user email:', userEmail);

    const query = `
      SELECT productname, price, url, order_number, checkout_date, weight
      FROM checkout
      WHERE email = $1 AND orderstatus::INTEGER < 4
      ORDER BY orderstatus::INTEGER DESC
    `;
    const result = await pool.query(query, [userEmail]);

    // console.log('orderdata', result.rows); // Log all rows received

    if (result.rows.length === 0) {
      return res.status(200).json([]); // Return an empty array if no orders
    }

    return res.json(result.rows); // ✅ Return all rows instead of wrapping only one
  } catch (error) {
    console.error('Error executing SQL query:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/add-product', async (req, res) => {
  const product = req.body;
  // console.log('products', product);

  const query = `
    INSERT INTO products (id, name, category, price, weight, url, stock, page, thumbnails, description, place, sizecolor, product_details, shipping)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);
  `;

  const values = [
  product.id,
  product.name,
  product.category,
  product.price ,
  product.weight,
  product.url,
  product.stock,
  product.page ,
  product.thumbnails,
  product.description,
  product.place,
  product.sizecolor,
  product.productdetails,
  product.shipping,
];

  try {
    // Execute the query and send success response
    await pool.query(query, values);
    res.status(200).json({ message: 'Product added successfully!' });
  } catch (err) {
    console.error('Error adding product:', err);

    // Send an error response
    res.status(500).json({ message: 'Failed to add product. Please try again.', error: err.message });
  }
});

app.get('/api/productsdata', async (req, res) => {
  try {
    const productCategory = req.query.category;
// console.log('productCategory', productCategory);
    const query = `
      SELECT id, name, category, price, weight, url, stock, page, thumbnails, 
             description, place, sizecolor, product_details, shipping, discount
      FROM products WHERE category = $1
    `;

    const result = await pool.query(query, [productCategory]);
    // console.log('Products data fetched:', result.rows);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No products found for the specified category' });
    }

    // Format data
    const formattedData = result.rows.map((product) => ({
      ...product,

      thumbnails: product.thumbnails?.[0]?.split(/\s+/).map((thumbnail) =>
        thumbnail.replace(/"/g,'')
      ) || [],
    }));

    // console.log('Formatted Products Data:', formattedData);

    return res.json(formattedData);
  } catch (error) {
    console.error('Error executing SQL query:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});



// Endpoint to fetch products based on category
app.get('/api/productscategory', async (req, res) => {
  const { category } = req.query; // Get the 'category' from query parameters

  try {
    // Query the products table in the database
    const query = category
      ? 'SELECT * FROM products WHERE category = $1' // Use a parameterized query
      : 'SELECT * FROM products'; // Get all products if no category is provided

    const params = category ? [category] : []; // Include the category parameter if provided

    const result = await pool.query(query, params); // Execute the query
    res.status(200).json(result.rows); // Send the rows as JSON to the client
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.get('/api/productsearch', async (req, res) => {
  const { name } = req.query;
  let query = null;
  let params = null;

  try {
    query = name
      ? `SELECT * FROM products WHERE name ILIKE '%' || $1 || '%' LIMIT $2 OFFSET $3;`
      : 'SELECT * FROM products LIMIT $2 OFFSET $3;';
    const limit = 10;
    const offset = 0;
    params = name ? [name, limit, offset] : [limit, offset];

    const result = await pool.query(query, params);

    // Format data
    const formattedData = result.rows.map((product) => ({
      ...product,
      thumbnails: product.thumbnails?.[0]?.split(/\s+/).map((thumbnail) =>
        thumbnail.replace(/"/g, '')
      ) || [],
    }));

    res.status(200).json(formattedData); // Send formattedData
  } catch (error) {
    console.error('Error fetching products:', error.message, { query, params });
    res.status(500).json({ error: 'An unexpected error occurred. Please try again later.' });
  }
});

app.get('/api/alldealsproduct', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE discount > 0 ');
  // Format data
    const formattedData = result.rows.map((product) => ({
      ...product,

      thumbnails: product.thumbnails?.[0]?.split(/\s+/).map((thumbnail) =>
        thumbnail.replace(/"/g,'')
      ) || [],
    }));

    // console.log('Formatted Products Data:', formattedData);
    res.status(200).json(formattedData); // Send formattedData
    
  } catch (error) {
    console.error('Error fetching featured products:', error);
    res.status(500).json({ error: 'Failed to fetch featured products' });
  }
});

app.get('/api/youmaylikeproducts', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE youmaylike = TRUE ');
  // Format data
    const formattedData = result.rows.map((product) => ({
      ...product,

      thumbnails: product.thumbnails?.[0]?.split(/\s+/).map((thumbnail) =>
        thumbnail.replace(/"/g,'')
      ) || [],
    }));

    // console.log('Formatted Youmaylike Data:', formattedData);
    res.status(200).json(formattedData); // Send formattedData
    
  } catch (error) {
    console.error('Error fetching youmaylike products:', error);
    res.status(500).json({ error: 'Failed to fetch youmaylike products' });
  }
});

app.get('/api/featuredproducts', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE featured = TRUE');
  // Format data
    const formattedData = result.rows.map((product) => ({
      ...product,

      thumbnails: product.thumbnails?.[0]?.split(/\s+/).map((thumbnail) =>
        thumbnail.replace(/"/g,'')
      ) || [],
    }));

    // console.log('Formatted Products Data:', formattedData);
    res.status(200).json(formattedData); // Send formattedData
    
  } catch (error) {
    console.error('Error fetching featured products:', error);
    res.status(500).json({ error: 'Failed to fetch featured products' });
  }
});

app.get('/api/bestsellingproducts', async (req, res) => {
  try {
    const resultBestSelling = await pool.query('SELECT * FROM products WHERE bestselling = TRUE');
  // Format data
    const formattedData = resultBestSelling.rows.map((product) => ({
      ...product,

      thumbnails: product.thumbnails?.[0]?.split(/\s+/).map((thumbnail) =>
        thumbnail.replace(/"/g,'')
      ) || [],
    }));

    // console.log('Formatted Products Data:', formattedData);
    res.status(200).json(formattedData); // Send formattedData
    
  } catch (error) {
    console.error('Error fetching bestselling products:', error);
    res.status(500).json({ error: 'Failed to fetch bestselling products' });
  }
});

app.get('/api/recommendedproducts', async (req, res) => {
  try {
    const resultRecommended = await pool.query('SELECT * FROM products WHERE recommended = TRUE');
  // Format data
    const formattedData = resultRecommended.rows.map((product) => ({
      ...product,

      thumbnails: product.thumbnails?.[0]?.split(/\s+/).map((thumbnail) =>
        thumbnail.replace(/"/g,'')
      ) || [],
    }));

    // console.log('Formatted Products Data:', formattedData);
    res.status(200).json(formattedData); // Send formattedData
    
  } catch (error) {
    console.error('Error fetching recommended products:', error);
    res.status(500).json({ error: 'Failed to fetch recommended products' });
  }
});


app.post('/installmentusers', uploadMultiple, async (req, res) => {
  const {
 firstname,
 lastname,
 email,
 // These should match the keys appended to FormData in the frontend
 address,      // Expecting req.body.address directly
 province,     // Expecting req.body.province directly
 phone,        // Expecting req.body.phone directly
 city,
 postalCode,
fullName,
 apartmentSuite, // This might need handling if frontend sends empty string
name,
quantity,
 total,
paymentOption,
installmentPlan,
installmentAmount,
 } = req.body;

  // Validation: Check if address is providednpm start

  if (!address) {
    return res.status(400).json({ error: 'Address is required.' });
  }

// Validate that both images are provided
  const installmentImageFile = req.files['installmentImage'] ? req.files['installmentImage'][0] : null;
  const selfieImageFile = req.files['selfie'] ? req.files['selfie'][0] : null;
  if (!installmentImageFile || !selfieImageFile) {
    return res.status(400).json({ error: 'Both ID image and selfie are required.' });
  }

 
  const startDate = new Date();
  startDate.setDate(startDate.getDate() + 30); // Add 32 days to the current date
  const endDate = new Date();
  endDate.setDate(endDate.getDate() + (30 * installmentPlan)); // Add 32 days to the current date

  const formattedStartDate = startDate.toDateString(); // Convert to a readable date format
  const formattedEndDate = endDate.toDateString(); // Convert to a readable date format

  try {
    const user = await pool.query('SELECT status FROM installmentusers WHERE email = $1 ORDER BY checkout_date DESC LIMIT 1', [email]);

    if (user.rows.length > 0) {
      const lastStatus = user.rows[0].status;
      if (lastStatus === 'pending') {
        return res.status(400).json({ error: 'You cannot submit the form while your application is pending.' });
      }
    }

    if (total < 500) {
      return res.status(500).json({ error: 'You cannot avail installment payment option if your total purchases is below 500' });
    }

    // // Upload images to S3
    // const uploadToS3 = async (file) => {
    //   const params = {
    //     Bucket: BucketName,
    //     Key: `${Date.now()}-${file.originalname}`,
    //     Body: file.buffer,
    //     ContentType: file.mimetype,
    //   };

    //   const result = await s3.upload(params).promise();
    //   return result.Location; // Returns the S3 URL
    // };

    // const imageUrl = await uploadToS3(installmentImageFile);
    // const selfieImageUrl = await uploadToS3(selfieImageFile);



    const cleanedTotal = parseFloat(total.replace(/[^0-9.-]+/g, ""));
    if (isNaN(cleanedTotal)) {
      return res.status(400).json({ error: 'Invalid total amount' });
    }

    const orderNumber = generateOrderNumber();

    const insertedOrder = await pool.query(
      `INSERT INTO installmentusers (firstname, lastname, email, address, province, phone, checkout_date, name, quantity, total, order_number, payment_option, status, usersimage, selected_plan, selected_amount, selfieimage) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', $13, $14, $15, $16) 
       RETURNING *`,
      [
        firstname,
        lastname,
        email,
        address,     // Frontend's 'streetAddress' becomes backend's 'address'
        province,    // Frontend's 'stateProvince' becomes backend's 'province'
        phone,         // Frontend's 'phoneNumber' becomes backend's 'phone'
        new Date(),
        name,
        quantity,
        cleanedTotal,  // Use the cleanedTotal here
        orderNumber,
        paymentOption,
       installmentImageFile,
        installmentPlan,
        installmentAmount,
       selfieImageFile,
      ]
    );

 
    // Prepare email data for customer
    const checkoutEmailToCustomer = {
      to: email,
      from: 'yeilvastore@gmail.com',
      subject: 'Checkout Information',
      html: `
        <html>
          <body>
            <div style="max-width: 600px; margin: auto; font-family: Arial, sans-serif; padding: 20px;">
              <h1 style="text-align: center;">Thank You for Your Order!</h1>
              <p>Dear ${firstname} ${lastname},</p>
              <p>We wanted to express our heartfelt thanks for choosing YeilvaSTORE for your recent purchase. Your order # ${orderNumber} has been received and is now being processed.</p>
              <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Order Details</h3>
              <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
                <p><strong>Product:</strong> ${name}</p>
                <p><strong>Total Amount:</strong> ${total}</p>
                 <p>Payment Method: ${paymentOption}</p>
                   <p>Installment Plan: ${installmentPlan}</p>
                   <p>Installment Payment monthly: ₱${installmentAmount}</p>
                <p>Your first Payment will start on ${formattedStartDate} and ends on ${formattedEndDate}. You will receive an email to notify you of your payment schedule.</p>
                <p><strong>Uploaded Image:</strong></p>
                <img src="${ installmentImageFile}" alt="Uploaded Image" style="max-width: 100%; height: auto;" />
                 <img src="${selfieImageFile}" alt="Uploaded Image" style="max-width: 100%; height: auto;" />
              </div>
              <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Shipping Address</h3>
              <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
                 <p><strong>Full name:</strong> ${fullName}</p>
                  <p><strong>Address:</strong> ${address}</p>
                 <p><strong>City:</strong> ${city}</p>
                  <p><strong>Province:</strong> ${province}</p>
                 <p><strong>Postal Code:</strong> ${postalCode}</p>
                <p><strong>Apartment:</strong> ${apartmentSuite}</p>
                  <p><strong>Phone:</strong> ${phone}</p>
              </div>
              <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at yeilvastore@gmail.com or 09497042268. We're here to help!</p>
              <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>
              <p>Best regards,</p>
              <p><a href="https://yeilvastore.com" target="_blank" rel="noopener noreferrer">YeilvaStore</a></p>
            </div>
          </body>
        </html>
      `,
    };

 const checkoutEmailToAdmin = async () => {
  const installmentAttachment = installmentImageFile
    ? {
        filename: 'installment_image.jpg',
        content: installmentImageFile.buffer,
        contentType: 'image/jpeg'
      }
    : null;

  const selfieAttachment = selfieImageFile
    ? {
        filename: 'selfie_image.jpg',
        content: selfieImageFile.buffer,
        contentType: 'image/jpeg'
      }
    : null;

  const mailOptions = {
    from: '"YeilvaStore" <yeilvastore@gmail.com>',
    to: 'bonz.ba50@gmail.com',
    subject: 'New Checkout Information',
    html: `
      <html>
        <body>
          <h1>New Order Received</h1>
          <p>Dear Admin,</p>
          <p>A new order has been received. Details are as follows:</p>
          <p>Username: ${firstname} ${lastname}</p>
          <p>Email Address: ${email}</p>
          <p>Product: ${name}</p>
          <p>Total Amount: ${total}</p>
          <p>Payment Method: ${paymentOption}</p>
          <p>Installment Plan: ${installmentPlan}</p>
          <p>Installment Payment monthly: ₱${installmentAmount}</p>
          <p>First Payment will start on ${formattedStartDate} and ends on ${formattedEndDate}. You will receive an email to notify you of your payment schedule.</p>
          <h5>Shipping Address</h5>
          <p><strong>Full name:</strong> ${fullName}</p>
          <p><strong>Address:</strong> ${address}</p>
          <p><strong>City:</strong> ${city}</p>
          <p><strong>Province:</strong> ${province}</p>
          <p><strong>Postal Code:</strong> ${postalCode}</p>
          <p><strong>Apartment:</strong> ${apartmentSuite}</p>
          <p><strong>Phone:</strong> ${phone}</p>
        </body>
      </html>
    `,
    attachments: [installmentAttachment, selfieAttachment].filter(Boolean)
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Admin email sent successfully:', info.response);
  } catch (error) {
    console.error('Error sending admin email:', error);
    res.status(500).json({ error: 'Failed to send admin email' });
  }
};

    // Send the emails
    await transporter.sendMail(checkoutEmailToCustomer);
    await checkoutEmailToAdmin();  // Call the admin email function

    console.log('Checkout information emails sent successfully');

    // Respond to the client
    res.json({ success: true, checkoutData: insertedOrder });

 } catch (error) {
    console.error('Error during checkout:', error);
    res.status(500).json({ error: 'Internal server error during checkout' }); // Fixed this line
  }
});



// Generate an order number
function generateOrderNumber() {
  const timestamp = new Date().getTime(); // Current timestamp
  const randomPart = Math.floor(Math.random() * 1000); // Random number (adjust as needed)
  const orderNumber = `${timestamp}-${randomPart}`;
  return orderNumber;
}

// Example route to create a new order
app.post('/create-order', async (req, res) => {
  try {
    // Generate the order number
    const orderNumber = generateOrderNumber();

    // Insert the order into the database (replace 'orders' with your table name)
    await pool.query('INSERT INTO installmentusers (order_number, ...other_fields) VALUES ($1, ...other_values)', [orderNumber, ...other_params]);

    // Respond with the generated order number
    res.status(201).json({ orderNumber });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'An error occurred while creating the order' });
  }
});



app.get('/api/user', async (req, res) => {
    try {
        const userEmail = req.query.email;
        // console.log('Received request for user email:', userEmail);

        // SQL query to fetch user details and all associated delivery addresses
        // It uses LEFT JOIN to include users even if they have no addresses.
        // json_agg collects all related addresses into a JSON array.
        // json_build_object formats each address into a clean object.
        // COALESCE handles cases where a user has no addresses, returning an empty array instead of null.
        const query = `
            SELECT
                u.firstname,
                u.lastname,
                u.email,
                TO_CHAR(u.timestamp, 'YYYY-MM-DD') AS joineddate,
                COALESCE(
                    json_agg(
                        json_build_object(
                            'id', uda.user_id,
                            'fullName', uda.full_name,
                            'streetAddress', uda.street_address,
                            'apartmentSuite', uda.apartment_suite,
                            'city', uda.city,
                            'stateProvince', uda.state_province,
                            'postalCode', uda.postal_code,
                            'phoneNumber', uda.phone_number,
                            'isDefault', uda.is_default
                        )
                        ORDER BY uda.is_default DESC, uda.created_at DESC -- Optional: Order addresses
                    ) FILTER (WHERE uda.id IS NOT NULL), -- Only aggregate if there's an actual address
                    '[]'::json -- Return an empty JSON array if no addresses
                ) AS delivery_addresses
            FROM
                users u
            LEFT JOIN
                user_delivery_addresses uda ON u.user_id = uda.user_id
            WHERE
                u.email = $1
            GROUP BY
                u.user_id -- Group by the primary key of the users table
        `;

        const result = await pool.query(query, [userEmail]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = result.rows[0];
        console.log('User data with addresses sent to client:', user);
        return res.json(user);

    } catch (error) {
        console.error('Error executing SQL query:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});




function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.route('/api/send-otp')
  .post(async (req, res) => {
    const { email } = req.body;


    // Check if the email exists in the users table
    try {
      const userExistsResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

      if (userExistsResult.rows.length === 0) {
        // User does not exist, return an error
        return res.status(404).json({ status: 'error', error: 'User not found' });
      }
    } catch (error) {
      console.error('Error checking if user exists:', error);
      return res.status(500).json({ status: 'error', error: 'An error occurred while checking user existence' });
    }


    // Generate OTP
    const otp = generateOTP();

    // Define the expiration duration for the OTP (e.g., 10 minutes)
    const expirationDurationMinutes = 10;
    const otpExpiration = new Date();
    otpExpiration.setMinutes(otpExpiration.getMinutes() + expirationDurationMinutes);

    // Send OTP via email
    try {
      await sendOTPEmail(email, otp);
    } catch (error) {
      console.error('Error sending OTP email:', error);
      return res.status(500).json({ status: 'error', error: 'Failed to send OTP email' });
    }

    // Update OTP and calculated expiration timestamp in the users table
    try {
      await pool.query('UPDATE users SET otp = $1, otp_expiration = $2 WHERE email = $3', [otp, otpExpiration, email]);
      console.log('OTP and otp_expiration updated successfully for user:', email);
      return res.json({ status: 'success' });
    } catch (error) {
      console.error('Error updating OTP and otp_expiration for user:', email, error);
      return res.status(500).json({ status: 'error', error: 'Failed to update OTP and otp_expiration' });
    }
  })
  .get((req, res) => {
    // Handle GET requests for /send-otp if needed
    // You can respond with information or redirect as appropriate
    res.status(404).send('Not Found');
  });


// Function to send OTP email using SendGrid
async function sendOTPEmail(email, otp) {
  const msg = {
    to: email,
    from: '"YeilvaStore" <yeilvastore@gmail.com>',
    subject: 'Password Reset OTP',
    text: `Your OTP is: ${otp}`,
  };

  try {
    await transporter.sendMail(msg);
    console.log('Email sent successfully');
  } catch (error) {
    console.error(error.toString());
  }
}



// Endpoint for OTP verification
app.route('/verify-otp').post(async (req, res) => {
  const { email, otp } = req.body;

  try {
    // Check if the OTP and email match an entry in the database
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND otp = $2 AND otp_expiration > NOW()',
      [email, otp]
    );

    if (result.rows.length > 0) {
      // OTP is valid
      // Optionally, you can delete only the OTP record from the database to prevent reuse
      const deleteResult = await pool.query(
        'UPDATE users SET otp = NULL, otp_expiration = NULL WHERE email = $1',
        [result.rows[0].email]
      );

      res.json({ status: 'success', message: 'OTP verified successfully' });
    } else {
      res.status(400).json({ status: 'error', error: 'Invalid or expired OTP' });
    }
  } catch (error) {
    console.error('Error during OTP verification:', error);
    res.status(500).json({ status: 'error', error: 'An error occurred during OTP verification' });
  }
});



app.post('/change-password', async (req, res) => {
  const { email, password } = req.body;

   const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  // Add OTP verification logic here if needed

  // Ensure that the user is authenticated and authorized before changing the password
  // You may use middleware or any other authentication method to ensure security

  try {
    // Replace 'user_id' with the actual user ID of the authenticated user
    // You can use the email to identify the user instead of user_id
    // Modify the query accordingly based on your database structure
    const updateResult = await pool.query('UPDATE users SET password = $1 WHERE email = $2', [
    hash, // Use the generated hash
    email,
  ]);


    if (updateResult.rowCount > 0) {
      res.json({ status: 'success' });
    } else {
      res.status(404).json({ status: 'error', error: 'User not found' });
    }
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ status: 'error', error: 'Failed to change password' });
  }
});


// Function to generate a random application number
function generateApplicationNumber() {
  const randomBytes = crypto.randomBytes(4); // Adjust the number of bytes as needed
  const applicationNumber = parseInt(randomBytes.toString('hex'), 16);
  return applicationNumber;
}


app.post('/api/saveLoanForm', uploadLoan, async (req, res) => {
  try {
    const { loanAmount, firstName, lastName, email, phone, gcash, address, installmentPlan, installmentAmount, birthday } = req.body;

    const installmentImageFile = req.files['image'] ? req.files['image'][0] : null;
    const selfieImageFile = req.files['selfieimage'] ? req.files['selfieimage'][0] : null;

    if (!installmentImageFile || !selfieImageFile) {
      return res.status(400).json({ error: 'Both ID image and selfie are required.' });
    }

    const startDate = new Date();
    startDate.setDate(startDate.getDate() + 30);
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + (30 * installmentPlan));

    const formattedStartDate = startDate.toDateString();
    const formattedEndDate = endDate.toDateString();

    const user = await pool.query('SELECT status FROM loanusers WHERE email = $1 ORDER BY created_at DESC LIMIT 1', [email]);

    if (user.rows.length > 0 && user.rows[0].status === 'pending') {
      return res.status(400).json({ error: 'You cannot submit the form while your application is pending.' });
    }

    const applicationNumber = generateApplicationNumber();

    const result = await pool.query(
      'INSERT INTO loanusers (loan_amount, first_name, last_name, email, phone_number, gcash_account, address, created_at, application_number, image, status, selected_plan, selected_amount, birthday, selfieimage) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, $8, $9, $10, $11, $12, $13, $14) RETURNING id',
      [loanAmount, firstName, lastName, email, phone, gcash, address, applicationNumber, installmentImageFile, 'pending', installmentPlan, installmentAmount, birthday, selfieImageFile]
    );

    const userId = result.rows[0].id;

    const emailResult = await sendLoanApplicationEmail(
      email, loanAmount, firstName, lastName, applicationNumber,
      phone, gcash, address, installmentImageFile, installmentPlan,
      installmentAmount, birthday, formattedStartDate, formattedEndDate, selfieImageFile
    );

    if (!emailResult.success) {
      console.error('Email failed:', emailResult.error);
      return res.status(500).json({ error: 'Loan saved, but email failed to send.' });
    }

    return res.status(200).json({ userId, applicationNumber });

  } catch (error) {
    console.error('Error saving loan form:', error);
    return res.status(500).json({ error: 'An error occurred while processing the loan application' });
  }
});


async function sendLoanApplicationEmail(
  email, loanAmount, firstName, lastName, applicationNumber,
  phone, gcash, address, installmentImageFile, installmentPlan,
  installmentAmount, birthday, formattedStartDate, formattedEndDate, selfieImageFile
) {
  const attachments = [];

  if (installmentImageFile) {
    attachments.push({
      filename: 'installment_image.jpg',
      content: installmentImageFile.buffer,
      contentType: 'image/jpeg'
    });
  }

  if (selfieImageFile) {
    attachments.push({
      filename: 'selfie_image.jpg',
      content: selfieImageFile.buffer,
      contentType: 'image/jpeg'
    });
  }

  const mailOptions = {
    from: '"YeilvaStore" <yeilvastore@gmail.com>',
    to: 'bonz.ba50@gmail.com',
    subject: 'New Loan Application',
    text: `
New loan application received!

Details:
Loan Amount: ₱${loanAmount}
Name: ${firstName} ${lastName}
Application no: ${applicationNumber}
Email: ${email}
Phone: ${phone}
Gcash Account: ${gcash}
Address: ${address}
Installment Plan: ${installmentPlan}
Installment Amount: ₱${installmentAmount}
Birthday: ${birthday}
First Payment will start on ${formattedStartDate} and ends on ${formattedEndDate}.
You will receive an email to notify you of your payment schedule.
    `,
    attachments
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.response);
    return { success: true };
  } catch (error) {
    console.error('Error sending email:', error);
    return { success: false, error };
  }
}


app.get('/api/loandata', async (req, res) => {
  try {
    const userEmail = req.query.email;
    // console.log('Received request for user email:', userEmail); 

   const query = 'SELECT phone_number, gcash_account, address, image FROM loanusers WHERE email = $1';

    const result = await pool.query(query, [userEmail]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }


    const user = result.rows[0];
    console.log('User data sent to client:', user);
    return res.json(user);

   
  } catch (error) {
    console.error('Error executing SQL query:', error); // Log the SQL query error
    return res.status(500).json({ error: 'Internal server error' });
  }
});



app.get('/validateCoupon', (req, res) => {
  const couponCode = req.query.code; // Get the coupon code from the request

  if (validCoupons[couponCode]) {
    // Coupon exists in the validCoupons object
    res.json({ valid: true, discount: validCoupons[couponCode].discount });
  } else {
    // Coupon does not exist or is invalid
    res.json({ valid: false, discount: 0 });
  }
});

app.get('/api/checkout-history', async (req, res) => {
  try {
    const userEmail = req.query.email;

    if (!userEmail) {
      return res.status(400).json({ error: 'Email parameter is missing' });
    }
const result = await db
  .select('productname', 'price', 'url', 'order_number', 'checkout_date', 'total', 'weight')
  .from('checkout')
  .where('email', userEmail);  


const query = db
   .select('productname', 'price', 'url', 'order_number', 'checkout_date', 'weight')
  .from('checkout')
  .where('email', userEmail)
  .toQuery();

// console.log('SQL Query:', query);
// console.log('Result:', result);

res.json(result);
  } catch (error) {
    console.error('Error fetching checkout history:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});


app.get('/api/loanform-history', async (req, res) => {
  try {
    const userEmail = req.query.email;

    if (!userEmail) {
      return res.status(400).json({ error: 'Email parameter is missing' });
    }
const result = await db
 .select( 'first_name', 'last_name', 'loan_amount', 'created_at', 'phone_number', 'application_number', 'address', 'gcash_account', 'status', 'payment1', 'payment1_date','payment2','payment2_date', 'payment3','payment3_date', 'payment4','payment4_date')
  .from('loanusers')
  .where('email', userEmail.replace(/"/g, ''));  // Remove extra quotes here


const query = db
  .select('first_name', 'last_name', 'loan_amount', 'created_at', 'phone_number', 'application_number', 'address', 'gcash_account', 'status', 'payment1', 'payment1_date','payment2','payment2_date', 'payment3','payment3_date', 'payment4','payment4_date')
  .from('loanusers')
  .where('email', userEmail)
  .toQuery();

// console.log('SQL Query:', query);
// console.log('Result:', result);

res.json(result);
  } catch (error) {
    console.error('Error fetching loan history:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});


app.post('/api/updatePayments', async (req, res) => {
  const {
    applicationNumber,
    payment1,
    payment1_date,
    payment2,
    payment2_date,
    payment3,
    payment3_date,
    payment4,
    payment4_date,
  } = req.body;

  try {
    // Perform database update for payments and payment dates
    await pool.query(
      'UPDATE loanusers SET payment1 = $1, payment1_date = $2, ' +
      'payment2 = $3, payment2_date = $4, ' +
      'payment3 = $5, payment3_date = $6, ' +
      'payment4 = $7, payment4_date = $8 ' +
      'WHERE application_number = $9',
      [payment1, payment1_date, payment2, payment2_date, payment3, payment3_date, payment4, payment4_date, applicationNumber]
    );

    res.json({ success: true, message: 'Payments updated successfully' });
  } catch (error) {
    console.error('Error updating payments:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});



// Endpoint to update status
app.post('/api/updateStatus', async (req, res) => {
  const { applicationNumber, newStatus } = req.body;

  try {
    // Perform database update for status
    await pool.query(
      'UPDATE loanusers SET status = $1 WHERE application_number = $2',
      [newStatus, applicationNumber]
    );

    res.json({ success: true, message: 'Status updated successfully' });
  } catch (error) {
    console.error('Error updating status:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


app.post('/api/adddeliveryaddress', async (req, res) => {
    const {
        fullName,
        userEmail,
        streetAddress,
        apartmentSuite,
        city,
        stateProvince,
        postalCode,
        phoneNumber,
         isDefault,
    } = req.body;
    // console.log('userEmail', userEmail);

    if (!userEmail) {
        return res.status(400).json({ success: false, message: 'User email is required.' });
    }

    let userId;
    try {
        // First, get the user_id from the users table using their email
        const userResult = await pool.query('SELECT user_id FROM users WHERE email = $1', [userEmail]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        userId = userResult.rows[0].user_id;
    } catch (error) {
        console.error('Error fetching user ID:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
    }

    try {
        await pool.query(
            `INSERT INTO user_delivery_addresses (
                user_id, full_name, street_address, apartment_suite, city, state_province, postal_code, phone_number, is_default
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [
                userId,
                fullName,
                streetAddress,
                apartmentSuite,
                city,
                stateProvince,
                postalCode,
                phoneNumber,
                 isDefault
            ]
        );

        res.json({ success: true, message: 'Address added successfully' });
    } catch (error) {
        console.error('Error adding new delivery address:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/installment-history', async (req, res) => {
  try {
    const userEmail = req.query.email;

    if (!userEmail) {
      return res.status(400).json({ error: 'Email parameter is missing' });
    }
const result = await db
 .select( 'total', 'name', 'checkout_date', 'order_number', 'address',  'phone', 'status', 'payment1', 'payment1_date','payment2','payment2_date', 'payment3','payment3_date', 'payment4','payment4_date')
  .from('installmentusers')
  .where('email', userEmail.replace(/"/g, ''));  // Remove extra quotes here


const query = db
   .select( 'total', 'name', 'checkout_date', 'order_number', 'address',  'phone', 'status', 'payment1', 'payment1_date','payment2','payment2_date', 'payment3','payment3_date', 'payment4','payment4_date')
  .from('installmentusers')
  .where('email', userEmail)
  .toQuery();

// console.log('SQL Query:', query);
// console.log('Result:', result);

res.json(result);
  } catch (error) {
    console.error('Error fetching loan history:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});



app.post('/api/updateInstallments', async (req, res) => {
  const {
    applicationNumber,
    payment1,
    payment1_date,
    payment2,
    payment2_date,
    payment3,
    payment3_date,
    payment4,
    payment4_date,
  } = req.body;

  try {
    // Perform database update for payments and payment dates
    await pool.query(
      'UPDATE installmentusers SET payment1 = $1, payment1_date = $2, ' +
      'payment2 = $3, payment2_date = $4, ' +
      'payment3 = $5, payment3_date = $6, ' +
      'payment4 = $7, payment4_date = $8 ' +
      'WHERE order_number = $9',
      [payment1, payment1_date, payment2, payment2_date, payment3, payment3_date, payment4, payment4_date, applicationNumber]
    );

    res.json({ success: true, message: 'Payments updated successfully' });
  } catch (error) {
    console.error('Error updating payments:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// Endpoint to update status
app.post('/api/installmentStatus', async (req, res) => {
  const { applicationNumber, newStatus } = req.body;

  try {
    // Perform database update for status
    await pool.query(
      'UPDATE installmentusers SET status = $1 WHERE order_number = $2',
      [newStatus, applicationNumber]
    );

    res.json({ success: true, message: 'Status updated successfully' });
  } catch (error) {
    console.error('Error updating status:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});





function authenticateJWT(req, res, next) {
  const token = req.cookies.jwtToken;

  if (!token) {
    console.log('No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.log('JWT verification failed:', err.message);
      return res.sendStatus(403);
    }

    req.user = user;
    console.log('User authenticated:', user);
    next();
  });
}



// Function to check if the provided credentials are valid
async function isValidCredentials(username, password) {
  try {
    const result = await pool.query('SELECT * FROM adminusers WHERE username = $1', [username]);
    
    return result.rows.length > 0 && bcrypt.compareSync(password, result.rows[0].password);
  } catch (error) {
    console.error('Error validating credentials', error);
    return false;
  }
}

const allowedOrigins = ['https://yeilvastore.com', 'https://www.yeilvastore.com'];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin); // Dynamically set the allowed origin
  }

  res.header('Access-Control-Allow-Credentials', true);
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  next();
});


app.post('/api/adminlogin', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (await isValidCredentials(username, password)) {
      const user = {
        userId: 'Admin1102',
        email: 'bonifacioamoren@gmail.com',
        role: 'admin',
      };

      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1hr' });
     
      res.cookie('jwtToken', token, { sameSite: 'None', secure: true, httpOnly: true });
       res.cookie('cherry','red', { sameSite: 'None', secure: true});

      // Send a success response
      res.json({ message: 'Login successful' });

    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login failed', error);
    res.status(500).json({ error: 'An error occurred during login' });
  }

  // Log the login attempt outside the try-catch block
  console.log('Login attempt for user:', username);
});


// Example registration endpoint
app.post('/api/adminregister', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // Generate a salt and hash the password
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    // Insert the user into the database
    await pool.query('INSERT INTO adminusers (username, password) VALUES ($1, $2)', [username, hashedPassword]);

    res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration failed', error);
    res.status(500).json({ error: 'An error occurred during registration' });
  }
});



// Define a route for deleting users
app.delete('/api/deleteInactiveUsers', async (req, res) => {
  try {
    // Calculate the timestamp 30 minutes ago
    const thirtyMinutesAgo = new Date(Date.now() - 30 * 60000); // 30 minutes * 60 seconds * 1000 milliseconds

    // Query to delete inactive users
    const deleteQuery = 'DELETE FROM users WHERE verified = false AND timestamp < $1';

    // Execute the query
    const result = await pool.query(deleteQuery, [thirtyMinutesAgo]);

    res.status(200).json({ message: 'Inactive users deleted successfully' });
  } catch (error) {
    console.error('Error deleting inactive users:', error);
    res.status(500).json({ error: 'An error occurred while deleting inactive users' });
  }
});


// Schedule the deletion job to run every day at midnight
cron.schedule('0 0 * * *', async () => {
  try {
    // Perform the deletion process
    const deleteQuery = 'DELETE FROM users WHERE verified = false AND timestamp < $1';
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60000); // 24 hours ago
    await pool.query(deleteQuery, [oneDayAgo]);
    console.log('Inactive users deleted successfully');
  } catch (error) {
    console.error('Error deleting inactive users:', error);
  }
});



app.post('/api/messages', async (req, res) => {
  const { email, mainMessage } = req.body;

  let client = null; // To ensure client release in all cases
  try {
    client = await pool.connect();  // Connect once

    // Check if email exists
    const queryCheckEmail = 'SELECT EXISTS(SELECT 1 FROM usershelp WHERE email = $1)';
    const resultCheckEmail = await client.query(queryCheckEmail, [email]);

    if (resultCheckEmail.rows[0].exists) {
      // Email exists, check if the responded flag is true or false
      const queryCheckResponded = 'SELECT responded FROM usershelp WHERE email = $1';
      const resultCheckResponded = await client.query(queryCheckResponded, [email]);

      if (resultCheckResponded.rows[0].responded === true) {  // Correctly checking for `false`
       // If responded is true, update message and reset responded flag
        const queryUpdate = 'UPDATE usershelp SET message = $2, responded = false WHERE email = $1';
        await client.query(queryUpdate, [email, mainMessage]);
        res.status(200).json({ status: 'success', message: 'Message created successfully.' });
      } else {
        // If responded is false
        res.status(400).json({status: 'failure', message: 'Failed to save message. User hasnt been responded to.' });
         
      }
    } else {
      // Email doesn't exist, insert a new record
      const queryInsert = 'INSERT INTO usershelp (email, message, responded, timestamp) VALUES ($1, $2, false, CURRENT_DATE)';
      await client.query(queryInsert, [email, mainMessage]);
      res.status(200).json({ status: 'success', message: 'Message created successfully.' });
    }

    client.release();  // Release the client at the end
  } catch (error) {
    if (client) {
      client.release();  // Ensure client release in case of error
    }
    console.error('Database error:', error);
    res.status(500).json({ status: 'failure', error: 'Internal server error.' });
  }
});


app.post('/api/reviews', async (req, res) => {
  const reviewData = req.body;

  try {
    // Here you can save the review data to your PostgreSQL database
    // console.log('Received review:', reviewData);
    await pool.query('INSERT INTO reviews (rating, comments, firstname, lastname, email, productname, submitted) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_DATE)', 
                    [reviewData.rating, reviewData.comment, reviewData.userData.firstname, reviewData.userData.lastname, reviewData.userData.email, reviewData.productname]);
    // Send a response back to the client
    res.status(200).send('Review received!');
  } catch(error) {
    console.error('Saving failed', error);
    res.status(500).json({ error: 'An error occurred during saving' });
  }
});


const cleanUpProductNameColumn = async () => {
  try {
    const query = `
      UPDATE checkout
       SET productname = REGEXP_REPLACE(productname, '[{}"]', '', 'g')
      WHERE productname ~ '[{}"]';
    `;

    const result = await pool.query(query);
    console.log('Clean up successful:', result.rowCount, 'rows updated');
  } catch (error) {
    console.error('Error cleaning up productname column:', error);
  }
};

app.get('/api/reviewstatus', async (req, res) => {

  await cleanUpProductNameColumn();

  const { userEmail, productName } = req.query;
  
  // console.log('Received parameters:', { userEmail, productName });
  
  if (!userEmail || !productName) {
    return res.status(400).json({ error: 'userEmail and productName are required' });
  }

  try {
    // Step 1: Check if the user has a checkout history for the product
    const checkoutQuery = `
      SELECT * FROM checkout 
      WHERE email = $1 AND productname =$2`;
    const checkoutResult = await pool.query(checkoutQuery, [userEmail, productName]);

    if (checkoutResult.rows.length === 0) {
      return res.status(404).json({ error: 'No checkout history for this product' });
    }

    // Step 2: Check if the user has already reviewed the product
    const reviewQuery = 'SELECT * FROM reviews WHERE email = $1 AND productname = $2';
    const reviewResult = await pool.query(reviewQuery, [userEmail, productName]);

    if (reviewResult.rows.length > 0) {
      return res.status(200).json({ reviewed: true, message: 'User has already reviewed this product' });
    }

    return res.status(200).json({ reviewed: false, message: 'User can write a review for this product' });
  } catch (error) {
    console.error('Error executing SQL query:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});


// Endpoint to fetch reviews based on product name
app.get('/api/userreviews', async (req, res) => {
  try {
    const { productName } = req.query;
    // Query the database for reviews based on product name
    const result = await pool.query('SELECT comments, email, rating FROM reviews WHERE productname = $1', [productName]);
    const reviews = result.rows.map(row => ({
      comments: row.comments,
      email: row.email,
      rating: row.rating
    }));
    // Send the fetched reviews as a response
    res.json(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


const Voucher = sequelize.define('Voucher', {
  code: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  discount: {
    type: DataTypes.DECIMAL,
    allowNull: false,
  },
  expirationDate: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
  },
    selected: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
});

// Sync the model with the database
sequelize.sync({ alter: true }).then(() => {
  console.log("Database & tables created!");
});

// Create a voucher
app.post('/api/vouchers', async (req, res) => {
  const { code, discount, expirationDate } = req.body;
  try {
    const voucher = await Voucher.create({ code, discount, expirationDate });
    res.json(voucher);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Validate a voucher
app.post('/api/vouchers/validate', async (req, res) => {
  const { code } = req.body;
  try {
    const voucher = await Voucher.findOne({ where: { code, isActive: true } });
    if (voucher && new Date(voucher.expirationDate) > new Date()) {
      // Deactivate the voucher after validation
      voucher.isActive = false;
      await voucher.save();
      res.json(voucher);
    } else {
      res.status(400).json({ error: 'Invalid or expired voucher' });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


// Schedule a task to run at 00:00 on the first day of every month
cron.schedule('0 0 1 * *', async () => {
  try {
    const currentDate = new Date();
    
    // Delete all vouchers that have expired
    const deleted = await Voucher.destroy({
      where: {
        expirationDate: {
          [Op.lt]: currentDate, // Vouchers with expirationDate less than the current date
        }
      }
    });

    console.log(`Deleted ${deleted} expired vouchers`);
  } catch (error) {
    console.error('Error deleting expired vouchers:', error);
  }
});


app.post('/registerfreecode', async (req, res) => {
    const { email, deviceInfo } = req.body;

    try {
        // Check if the user already exists
        const userResult = await pool.query('SELECT * FROM freevoucher WHERE email = $1', [email]);

        if (userResult.rows.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Check if the device already exists, with explicit casting
        const userDevice = await pool.query('SELECT * FROM freevoucher WHERE device_info::jsonb @> $1::jsonb', [JSON.stringify(deviceInfo)]);

        if (userDevice.rows.length > 0) {
            return res.status(400).json({ error: 'User already registered' });
        }

        // Insert the new user and device information
        const insertUserQuery = 'INSERT INTO freevoucher (email, device_info) VALUES ($1, $2) RETURNING id';
        const newUser = await pool.query(insertUserQuery, [email, JSON.stringify(deviceInfo)]);
        const userId = newUser.rows[0].id;

      // Select an active voucher
        const voucherResult = await pool.query('SELECT code FROM "Vouchers" WHERE discount = 15 AND selected = false AND "isActive" = true LIMIT 1');
        if (voucherResult.rows.length === 0) {
            return res.status(400).json({ error: 'No Discount Voucher available' });
        }

        const voucherCode = voucherResult.rows[0].code;

        // Mark the voucher as inactive
        await pool.query('UPDATE "Vouchers" SET selected = true WHERE code = $1', [voucherCode]);

        // Send the voucher code via email
        await sendEmail(email, voucherCode);
          // Mark the user as having received a voucher
        await pool.query('UPDATE freevoucher SET hasreceivedvoucher = true WHERE id = $1', [userId]);

        res.json({ success: 'User registered and voucher sent successfully' });

    } catch (error) {
        console.error('Error registering user:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});


const sendEmail = async (email, voucherCode) => {
    const msg = {
        to: email,
        from: '"YeilvaStore" <yeilvastore@gmail.com>',
        subject: 'Your Discount Voucher',
        text: `Congratulations! Here is your discount voucher code: ${voucherCode}`,
        html: `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Your Discount Voucher</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                .container {
                    width: 100%;
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }
                .header {
                    text-align: center;
                    padding: 20px 0;
                    background-color: #232f3e;
                    color: #ffffff;
                    border-top-left-radius: 10px;
                    border-top-right-radius: 10px;
                }
                .header h1 {
                    margin: 0;
                    font-size: 24px;
                }
                .body {
                    padding: 20px;
                }
                .body p {
                    font-size: 16px;
                    line-height: 1.5;
                    color: #333333;
                }
                .voucher-code {
                    font-size: 20px;
                    font-weight: bold;
                    background-color: #f0f0f0;
                    padding: 10px;
                    text-align: center;
                    margin: 20px 0;
                    border-radius: 5px;
                    border: 1px solid #dddddd;
                }
                .footer {
                    text-align: center;
                    padding: 20px 0;
                    background-color: #f0f0f0;
                    color: #888888;
                    border-bottom-left-radius: 10px;
                    border-bottom-right-radius: 10px;
                }
                .footer p {
                    margin: 0;
                    font-size: 12px;
                }
                .body a {
                    color: #1a73e8;
                    text-decoration: none;
                }
                .body a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Yeilva Store</h1>
                </div>
                <div class="body">
                    <p>Congratulations!</p>
                    <p>We are excited to offer you a 15% discount voucher for your next purchase. Use the code below at checkout:</p>
                    <div class="voucher-code">${voucherCode}</div>
                    <p>Thank you for shopping with us!</p>
                    <p><a href="https://yeilvastore.com" target="_blank" rel="noopener noreferrer">Shop Now</a></p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 Yeilva Store. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>`,
    };

    try {
        await transporter.sendMail(msg);
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
    }
};

app.post('/openraffle', async (req, res) => {
  const { fullname, email, deviceInfo } = req.body;

  try {
    // Check if the email already exists
    const emailResult = await pool.query('SELECT email FROM raffleopen WHERE email = $1', [email]);
    if (emailResult.rows.length > 0) {
      // Email already exists
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check if the device already exists by comparing specific fields from the JSON
    const userDevice = await pool.query(
      `SELECT * FROM raffleopen WHERE device_info::text = $1::text`, 
      [JSON.stringify(deviceInfo)]
    );

    if (userDevice.rows.length > 0) {
      return res.status(400).json({ error: 'User already registered' });
    }

    // Insert the new raffle entry
    const query = 'INSERT INTO raffleopen (fullname, email, submitted, device_info) VALUES ($1, $2, $3, $4)';
    const values = [fullname, email, new Date(), deviceInfo];
    await pool.query(query, values);

    // Send the success response
    res.json({ success: true });

    // Send the email asynchronously after responding to the client
    openRaffleEmail(email, fullname)
      .then(() => console.log('Email sent successfully'))
      .catch((err) => console.error('Error sending email:', err));

  } catch (error) {
    console.error('Error storing raffle entry:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Server error' });
    }
  }
});



const openRaffleEmail = async (email, fullname) => {
    const msg = {
        to: email,
        from: '"YeilvaStore" <yeilvastore@gmail.com>',
        subject: 'Congratulations on Your Raffle Registration!',
        text: `Dear ${fullname}, Congratulations! Your raffle entry has been successfully submitted.`,
        html: `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Raffle Registration Confirmation</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                .container {
                    width: 100%;
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }
                .header {
                    text-align: center;
                    padding: 20px 0;
                    background-color: #232f3e;
                    color: #ffffff;
                    border-top-left-radius: 10px;
                    border-top-right-radius: 10px;
                }
                .header h1 {
                    margin: 0;
                    font-size: 24px;
                }
                .body {
                    padding: 20px;
                    color: #333333;
                }
                .body p {
                    font-size: 16px;
                    line-height: 1.6;
                }
                .voucher-code {
                    font-size: 18px;
                    font-weight: bold;
                    background-color: #f0f0f0;
                    padding: 10px;
                    text-align: center;
                    margin: 20px 0;
                    border-radius: 5px;
                    border: 1px solid #dddddd;
                    color: #333333;
                }
                .footer {
                    text-align: center;
                    padding: 20px 0;
                    background-color: #f0f0f0;
                    color: #888888;
                    border-bottom-left-radius: 10px;
                    border-bottom-right-radius: 10px;
                }
                .footer p {
                    margin: 0;
                    font-size: 12px;
                }
                .body a {
                    color: #1a73e8;
                    text-decoration: none;
                }
                .body a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Yeilva Store</h1>
                </div>
                <div class="body">
                    <p>Dear ${fullname},</p>
                    <p>We are thrilled to inform you that your raffle entry has been successfully submitted!</p>
                    <p>Your raffle ticket details:</p>
                    <div class="voucher-code">${fullname} - ${email}</div>
                    <p>Thank you for participating in our raffle. We wish you the best of luck!</p>
                    <p>Meanwhile, feel free to explore our latest products and offers:</p>
                    <p><a href="https://yeilvastore.com" target="_blank" rel="noopener noreferrer">Visit Yeilva Store</a></p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 Yeilva Store. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>`,
    };

    try {
         await transporter.sendMail(msg);
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
    }
};

// Endpoint to randomly select two winning tickets
app.get('/openraffle/winner', async (req, res) => {
  try {
    const result = await pool.query('SELECT fullname, email FROM raffleopen');
    const participants = result.rows;

    if (participants.length === 0) {
      return res.status(404).json({ error: 'No participants found' });
    }

    const shuffled = participants.sort(() => 0.5 - Math.random());
    const firstWinner = shuffled[0];
    const secondWinner = shuffled[1];

    res.json({
      firstWinnerEmail: firstWinner.email,
      firstWinnerName: firstWinner.fullname,
      secondWinnerEmail: secondWinner.email,
      secondWinnerName: secondWinner.fullname,
    });
  } catch (error) {
    console.error('Error selecting winners:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


app.post('/newsletter', async (req, res) => {
  const { fullname, email } = req.body;

  try {
    // Check if the email already exists
    const emailResult = await pool.query('SELECT email FROM newsletter WHERE email = $1', [email]);
    if (emailResult.rows.length > 0) {
      // Email already exists
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Insert the new newsletter entry
    const query = 'INSERT INTO newsletter (fullname, email, submitted) VALUES ($1, $2, $3)';
    const values = [fullname, email, new Date()];
    await pool.query(query, values);

    // Send the success response
    res.json({ success: true });

    // Send the email asynchronously after responding to the client
    newsLetterEmail(email, fullname)
      .then(() => console.log('Email sent successfully'))
      .catch((err) => console.error('Error sending email:', err));

  } catch (error) {
    console.error('Error storing subscribe entry:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Server error' });
    }
  }
});


const newsLetterEmail = async (email, fullname) => {
    const msg = {
        to: email,
        from: 'yeilvastore@gmail.com', // Your verified SendGrid sender email
        subject: 'Welcome to Yeilva Store: You’re Subscribed!',
        text: `Dear ${fullname}, Congratulations! You're now successfully subscribed to the Yeilva Store Newsletter.`,
        html: `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to Yeilva Store</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                    color: #333333;
                }
                .container {
                    max-width: 600px;
                    margin: 20px auto;
                    background-color: #ffffff;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                }
                .header {
                    background-color: #232f3e;
                    color: #ffffff;
                    text-align: center;
                    padding: 20px;
                }
                .header h1 {
                    margin: 0;
                    font-size: 28px;
                }
                .body {
                    padding: 20px;
                }
                .body p {
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 16px 0;
                }
                .voucher-code {
                    background-color: #f9f9f9;
                    border: 1px solid #dedede;
                    padding: 12px;
                    text-align: center;
                    font-size: 18px;
                    margin: 24px 0;
                    border-radius: 4px;
                    color: #333;
                }
                .action-button {
                    display: inline-block;
                    padding: 12px 20px;
                    background-color: #1a73e8;
                    color: white;
                    text-align: center;
                    text-decoration: none;
                    border-radius: 4px;
                    margin: 20px 0;
                    font-size: 16px;
                }
                .footer {
                    background-color: #f4f4f4;
                    text-align: center;
                    padding: 15px 0;
                    font-size: 14px;
                    color: #777;
                }
                .footer a {
                    color: #1a73e8;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to Yeilva Store!</h1>
                </div>
                <div class="body">
                    <p>Hi ${fullname},</p>
                    <p>Thank you for subscribing to the Yeilva Store newsletter! You’re now part of our exclusive community, and you’ll be the first to know about:</p>
                    <ul>
                        <li>Special discounts and promotions</li>
                        <li>Exclusive freebies and giveaways</li>
                        <li>New product launches</li>
                    </ul>
                    <p>As a token of our appreciation, here are your subscription details:</p>
                    <div class="voucher-code">
                        Name: ${fullname}<br />
                        Email: ${email}
                    </div>
                    <p>We’re excited to have you with us, and we’re sure you’ll love our upcoming deals. Stay tuned for exciting offers in your inbox soon!</p>
                    <p>In the meantime, feel free to <a href="https://yeilva-store.up.railway.app" target="_blank" rel="noopener noreferrer">visit our store</a> and explore our latest products.</p>
                    <a class="action-button" href="https://yeilva-store.up.railway.app" target="_blank" rel="noopener noreferrer">Shop Now</a>
                </div>
                <div class="footer">
                    <p>&copy; 2024 Yeilva Store. All rights reserved.</p>
                    <p><a href="https://yeilvastore.com/unsubscribe" target="_blank">Unsubscribe</a> | <a href="https://yeilvastore.com/privacy-policy" target="_blank">Privacy Policy</a></p>
                </div>
            </div>
        </body>
        </html>
        `,
    };

    try {
        await transporter.sendMail(msg);
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
    }
};


// Function to send the transaction confirmation email
async function sendTransactionEmail({ email, firstname, lastname, transactionCode, amount }) {
  const internalEmail = {
    to: 'ayeilvzarong@gmail.com',
    from: 'yeilvastore@gmail.com',
    subject: 'GCash Transaction - Confirmation Needed',
    text: `Dear Team,

A payment transaction has been received. Below are the details for confirmation:

Transaction Code: ${transactionCode}
Amount Paid: ${amount} PHP
Customer Email: ${email}

Please verify and process this transaction accordingly.

Best regards,
YeilvaSTORE`,
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>Transaction Confirmation Needed</h2>
        <p>Dear Team,</p>
        <p>A payment transaction has been received. Below are the details for confirmation:</p>
        <ul>
          <li><strong>Transaction Code:</strong> ${transactionCode}</li>
          <li><strong>Amount Paid:</strong> ${amount} PHP</li>
          <li><strong>Customer Email:</strong> ${email}</li>
        </ul>
        <p>Please verify and process this transaction accordingly.</p>
        <p>Best regards,<br>YeilvaSTORE</p>
      </div>
    `,
  };

  const customerEmail = {
    to: email,
    from: 'yeilvastore@gmail.com',
    subject: 'GCash Transaction - Payment Received',
    text: `Dear ${firstname} ${lastname},

Thank you for your payment. Below are the details of your transaction:

Transaction Code: ${transactionCode}
Amount Paid: ${amount} PHP
Email: ${email}

Please keep this email as confirmation of your payment. If you have any questions, contact us at yeilvastore.

Thank you for choosing YeilvaSTORE.

Best regards,
YeilvaSTORE`,
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>Transaction Confirmation</h2>
        <p>Dear ${firstname} ${lastname},</p>
        <p>Thank you for your payment. Below are the details of your transaction:</p>
        <ul>
          <li><strong>Transaction Code:</strong> ${transactionCode}</li>
          <li><strong>Amount Paid:</strong> ${amount} PHP</li>
          <li><strong>Email:</strong> ${email}</li>
        </ul>
        <p>Please keep this email as confirmation of your payment. If you have any questions, contact us at <a href="mailto:yeilvastore@gmail.com">yeilvastore</a>.</p>
        <p>Thank you for choosing YeilvaSTORE.</p>
        <p>Best regards,<br>YeilvaSTORE</p>
        <p><a href="https://yeilvastore.com" target="_blank" rel="noopener noreferrer">Visit Our Store</a></p>
      </div>
    `,
  };

  try {
    // Send email to the internal team
    await transporter.sendMail(internalEmail);
    console.log(`Internal transaction email sent successfully to ${internalEmail.to}`);

    // Send confirmation email to the customer
     await transporter.sendMail(customerEmail);
    console.log(`Customer confirmation email sent successfully to ${email}`);
  } catch (error) {
    console.error('Error sending transaction emails:', error);
  }
}


// Endpoint to save transaction code and user details
app.post('/api/save-transaction-code', async (req, res) => {
  const { transactionCode, amount, firstname, lastname, email } = req.body;

  const query = `
    INSERT INTO gcashpayment (gcashcode, amount, firstname, lastname, email, submitteddate, status)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
  `;

  try {
    // Execute the query, passing in all the parameters including the status
    await pool.query(query, [transactionCode, amount, firstname, lastname, email, new Date(), 'none']);

    // Send confirmation email only after successful database entry
    await sendTransactionEmail({ email, firstname, lastname, transactionCode, amount });

    // Send success response to the client
    res.status(201).json({ message: 'Transaction saved and email sent successfully' });
  } catch (error) {
    console.error('Error saving transaction or sending email:', error);
    res.status(500).json({ message: 'Error saving transaction or sending email' });
  }
});



app.post('/gcashsettlement', async (req, res) => {
  const { firstname, lastname, email, amount, transactionCode, purpose, deadline } = req.body;

  try {
    // Insert form data into the database
    const result = await pool.query(
      `INSERT INTO gcash_settlements(firstname, lastname, email, amount, transaction_code, purpose, deadline, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [firstname, lastname, email, parseFloat(amount), transactionCode, purpose, deadline, new Date()]
    );

    const transaction = result.rows[0];

    // Prepare the email content
    const emailContent = {
      to: email,
      from: 'yeilvastore@gmail.com', // Your verified sender email
      subject: 'Your GCash Settlement Details',
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <p>Dear ${firstname} ${lastname},</p>
          <p>Thank you for using our GCash settlement service. Please find the details below to settle your amount:</p>
          <ul>
            <li><strong>Amount:</strong> PHP ${amount}</li>
            <li><strong>Transaction Code:</strong> ${transactionCode}</li>
            <li><strong>Purpose:</strong> ${purpose}</li>
            <li><strong>Deadline:</strong> ${deadline}</li>
          </ul>
          <p style="text-align: center; margin: 20px 0;">
            <a href="https://yeilvastore.com/gcashtorecieved/" 
               style="
                 display: inline-block;
                 padding: 10px 20px;
                 font-size: 16px;
                 color: #fff;
                 background-color: #007bff;
                 text-decoration: none;
                 border-radius: 5px;
               " 
               target="_blank" 
               rel="noopener noreferrer">
              PAY NOW
            </a>
          </p>
          <p>If you have any questions, feel free to <a href="https://yeilvastore.com/contact" target="_blank">contact us</a>.</p>
          <p>Best regards,</p>
          <p><strong>Yeilva Store Team</strong></p>
        </div>
      `,
    };

    // Send the email
    await transporter.sendMail(emailContent);

    // Respond to the frontend
    res.status(200).json({
      message: 'Transaction recorded successfully and email sent!',
      transaction,
    });
  } catch (error) {
    console.error('Error processing transaction:', error);
    res.status(500).json({ error: 'An error occurred while processing the transaction.' });
  }
});


app.get('/gcash_received', async (req, res) => {
  // console.log('Received Query Params:', req.query); 

  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Query to fetch the most recent record for the email, including the status column
    const query = `
      SELECT amount, deadline, purpose, transaction_code, email, status
      FROM gcash_settlements
      WHERE email = $1
      ORDER BY created_at DESC
      LIMIT 1
    `;
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No settlements found for this email' });
    }

    const latestEntry = result.rows[0];

    // Check if the status is false
    if (latestEntry.status) {
      return res.status(403).json({ 
        error: 'The latest settlement for this email has been marked as completed.' 
      });
    }

    return res.status(200).json(latestEntry);
  } catch (error) {
    console.error('Error processing transaction:', error);
    return res.status(500).json({ error: 'An error occurred while processing the transaction.' });
  }
});


app.post('/receivedgcash', async (req, res) => {
  const { firstname, lastname, email, amount, transactionCode, purpose, deadline } = req.body;

  try {
    // Insert form data into the gcash_setrecieved table
    const result = await pool.query(
      `INSERT INTO gcash_setrecieved (firstname, lastname, email, amount, transaction_code, purpose, deadline, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [firstname, lastname, email, parseFloat(amount), transactionCode, purpose, deadline, new Date()]
    );

    // Update the status column in the gcash_settlements table
    await pool.query(
      `UPDATE gcash_settlements 
       SET status = $1 
       WHERE email = $2 AND transaction_code = $3`,
      [true, email, transactionCode]
    );

    res.status(201).json({ 
      message: 'Transaction recorded successfully, and status updated', 
      data: result.rows[0] 
    });

  } catch (error) {
    console.error('Error processing transaction:', error);
    res.status(500).json({ error: 'An error occurred while processing the transaction.' });
  }
});



app.post('/api/booking', async (req, res) => {
  const {
    fullName,
    email,
    departureCity,
    arrivalCity,
    departureDate,
    returnDate,
    birthday,
    address,
    passengers,
    phone,
    class: travelClass,
    transactionCode,
    accountName,
  } = req.body;

  const query = `
    INSERT INTO bookings
    (full_name, email, departure_city, arrival_city, departure_date, return_date, birthday, address, passengers, phone, travel_class, submitted_date, transaction_code, account_name)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
    RETURNING id
  `;

  const values = [
    fullName,
    email,
    departureCity,
    arrivalCity,
    departureDate || null,
    returnDate || null,
    birthday || null,
    address,
    passengers,
    phone.toString(), // Convert phone to a string
    travelClass,
    new Date(),
    transactionCode,
    accountName,
  ];

  try {
    // Insert booking into database
    const result = await pool.query(query, values);
    const bookingId = result.rows[0].id;

    // Send email using SendGrid
    const emailContent = `
      <h1>Booking Confirmation</h1>
      <p>Thank you for your booking, ${accountName}!</p>
      <p><strong>Transaction Code:</strong> ${transactionCode}</p>
      <p><strong>Passenger Name:</strong> ${fullName}</p>
      <p><strong>Booking Details:</strong></p>
      <ul>
        <li><strong>Departure City:</strong> ${departureCity}</li>
        <li><strong>Arrival City:</strong> ${arrivalCity}</li>
        <li><strong>Departure Date:</strong> ${departureDate || 'N/A'}</li>
        <li><strong>Return Date:</strong> ${returnDate || 'N/A'}</li>
        <li><strong>Passengers:</strong> ${passengers}</li>
        <li><strong>Travel Class:</strong> ${travelClass}</li>
        <li><strong>Phone:</strong> ${phone}</li>
        <li><strong>Email:</strong> ${email}</li>
        <li><strong>Address:</strong> ${address}</li>

      </ul>
       <p><a href="https://yeilvastore.com" target="_blank" rel="noopener noreferrer">Visit Yeilva Store</a></p>
        <p>Best regards,</p>
        <p>Yeilva Store Team</p>
    `;

    const msg = {
      to: 'bonz.ba50@gmail.com', // Recipient email
      from: 'yeilvastore@gmail.com', // Your verified sender email
      subject: `Booking Confirmation - ${transactionCode}`,
      html: emailContent,
    };

   await transporter.sendMail(msg);

    // Respond with success message
    res.status(201).json({
      message: 'Booking successfully created and email sent',
      bookingId,
    });
  } catch (error) {
    console.error('Error processing booking:', error);

    // Determine if email-related error occurred
    if (error.response) {
      console.error(error.response.body);
    }

    res.status(500).json({
      message: 'Error processing your booking. Please try again.',
    });
  }
});


const PAYMONGO_API_URL = 'https://api.paymongo.com/v1/checkout_sessions';
const PAYMONGO_SECRET_KEY = process.env.PAYMONGO_SECRET_KEY;
const VALID_VOUCHER_CODE = 'SAVE10'; // A hardcoded example for demonstration
const VOUCHER_DISCOUNT_PERCENTAGE = 10;
const SHIPPING_FEE_PESOS = 150; 
const FREE_SHIPPING_THRESHOLD = 2500;

app.post('/create-checkout-session', async (req, res) => {
  try {
    const rawLineItems = req.body.data.attributes.line_items;
    const voucherCode = req.body.data.attributes.voucher_code; // Get the voucher code from the client

    let totalItemsPrice = rawLineItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    // Calculate shipping fee
    let shippingRate = 0;
    if (totalItemsPrice < FREE_SHIPPING_THRESHOLD) {
      // Your shipping calculation logic
      const totalWeight = rawLineItems.reduce((total, item) => total + (item.weight || 0), 0);
      const newMultiplier = totalWeight > 0 ? (0.145 + 30 / totalWeight) : 0;
      shippingRate = Math.round(
        rawLineItems.reduce((total, item) => total + (item.weight || 0) * newMultiplier, 0)
      );
    }
    
    // Validate the voucher code and apply the discount
    let voucherDiscount = 0;
    if (voucherCode === VALID_VOUCHER_CODE) { // Basic validation
      voucherDiscount = totalItemsPrice * (VOUCHER_DISCOUNT_PERCENTAGE / 100);
    }

    // Prepare line items for PayMongo
    const paymongoLineItems = rawLineItems.map(item => ({
      name: item.name,
      quantity: item.quantity,
      amount: item.price * 100, // Price in centavos
      currency: 'PHP',
    }));

    if (shippingRate > 0) {
      paymongoLineItems.push({
        name: 'Shipping Fee',
        quantity: 1,
        amount: shippingRate * 100,
        currency: 'PHP',
      });
    }

    if (voucherDiscount > 0) {
      paymongoLineItems.push({
        name: `Voucher Discount (${VOUCHER_DISCOUNT_PERCENTAGE}%)`,
        quantity: 1,
        amount: -voucherDiscount * 100, // Negative amount for discounts
        currency: 'PHP',
      });
    }

    // Send the final payload to PayMongo
    const payload = {
      data: {
        attributes: {
          line_items: paymongoLineItems,   
          send_email_receipt: true,
          show_description: true,
          show_line_items: true,
          success_url: 'https://yeilvastore.com/successpage', // Redirect URL on success
          cancel_url: 'https://yeilvastore.com/cancelpage',   // Redirect URL on cancel
          description: 'Payment for your order',
          statement_descriptor: 'yeilvastore',
          payment_method_types: ['card', 'gcash', 'paymaya', 'dob'], 
        },
      },
    };
    const response = await axios.post(PAYMONGO_API_URL, payload, {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Basic ${Buffer.from(PAYMONGO_SECRET_KEY).toString('base64')}`,
      },
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error creating checkout session:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'An error occurred' });
  }
});



const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
