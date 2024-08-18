const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto =require('crypto');
const cors = require('cors');
const knex = require('knex');
const cron = require('node-cron');
const sgMail = require('@sendgrid/mail');
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
const upload = multer({ storage: storage });
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const checkAuthRouter = require('./Routes/checkAuth');
require('dotenv').config({ path: 'sendgrid.env' });
require('dotenv').config({ path: 'paymongo.env' });
require('dotenv').config({ path: 'tokensecret.env' });
require('dotenv').config({ path: 's3.env' });
require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');


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
  origin: 'https://yeilva-store.up.railway.app', 
  credentials: true,
}));

app.use(cookieParser());


app.use('/api/check-auth', checkAuthRouter);


const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
sgMail.setApiKey(SENDGRID_API_KEY);



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
  // console.log('Request body:', req.body);

 const salt = bcrypt.genSaltSync(10);
const hash = bcrypt.hashSync(password, salt);


  try {
    // Check if the email already exists in the users table
    const existingUser = await db('users').where('email', '=', email);

    if (existingUser.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Generate a confirmation token
    const token = generateToken();

    // Store the token in the PostgreSQL database
    await db('users').insert({
      firstname: firstname,
      lastname: lastname,
      email: email,
      password: hash,
      // Store the confirmation token and set verified to false
      token: token,
      verified: false,
       status: 'active', // Set the initial status to 'active'
       timestamp: new Date(),
    });

    // Craft the confirmation link
    const verificationLink = `https://yeilva-store.up.railway.app/confirm?token=${token}`;

    // Craft the confirmation email
    const msg = {
      to: email,
      from: 'yeilvastore@gmail.com',
      subject: 'Email Verification',
      html: `<html>
      <body>
      <div>
      <p>Dear ${firstname} ${lastname},</p>
      <p>Thank you for signing up! To verify your email address, please click the link below:</p> 
      <a href="${verificationLink}">Verification Link</a>
      <p>If you have any questions, feel free to reply to this email.</p>

      <p>Best regards,</p>
      <p>YeilvaSTORE</p>
      </div>
      </body>
      </html>`,
    };

    // Send the confirmation email
    sgMail.send(msg, (error) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).json({ error: 'Failed to send email' });
      }
      console.log('Email sent successfully');
      res.json({ message: 'Email sent successfully' });
    });
  } catch (err) {
    console.error('Error during registration', err);
    res.status(500).json('An error occurred during registration');
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
    address,
    province,
    phone,
    name,
    quantity,
    total,
    paymentOption, 
    productNames,
  } = req.body;

  try {
       const cleanTotal = cleanNumericValue(total); // Clean the total value
    // Start a database transaction
    await db.transaction(async (trx) => {
      // Generate the order number
      const orderNumber = generateOrderNumber();

      // Insert data into the 'checkout' table, including the order number and new fields
      const insertedOrder = await trx('checkout')
        .insert({
          firstname, 
          lastname, 
          email,
          address,
          province,
          phone,
          checkout_date: new Date(),
          name,
          quantity,
        total: cleanTotal,  // Insert cleaned total
          order_number: orderNumber,
          payment_option: paymentOption,
          productname: productNames,
        })
        .returning('*');

      // Send a success response with the inserted data
      res.json({ success: true, checkoutData: insertedOrder });


        // Send an email with the checkout information to the customer
        const checkoutInfoEmailToCustomer = {
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
            <p><strong>Payment Method:</strong> ${paymentOption}</p>
          </div>

          <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Shipping Address</h3>

          <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
            <p><strong>Address:</strong> ${address}</p>
            <p><strong>Province:</strong> ${province}</p>
            <p><strong>Phone:</strong> ${phone}</p>
          </div>

          <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at [yeilvastore@gmail.com] or [09497042268]. We're here to help!</p>

          <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>

          <p>Best regards,</p>
          <p>YeilvaSTORE</p>
        </div>
      </body>
    </html>
          `,
        }; 

       
      // Send an email with the checkout information to the admin
const checkoutInfoEmailToAdmin = {
  to: 'ayeilva@yahoo.com',
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
            <p><strong>Total Amount:</strong> ${total}</p>
            <p><strong>Payment Method:</strong> ${paymentOption}</p>
          </div>

          <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Shipping Address</h3>

          <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
            <p><strong>Address:</strong> ${address}</p>
            <p><strong>Province:</strong> ${province}</p>
            <p><strong>Phone:</strong> ${phone}</p>
          </div>

          <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at [yeilvastore@gmail.com] or [09497042268]. We're here to help!</p>

          <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>

          <p>Best regards,</p>
          <p>YeilvaSTORE</p>
        </div>
      </body>
    </html>
  `,
};


       try {
  // Send checkout info email to customer
  await sgMail.send(checkoutInfoEmailToCustomer);
  // Send checkout info email to admin
  await sgMail.send(checkoutInfoEmailToAdmin);
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


app.get('/api/checkoutdata', async (req, res) => {
  try {
    const userEmail = req.query.email;
    console.log('Received request for user email:', userEmail); // Add this line for debugging

   const query = 'SELECT address, province, phone FROM checkout WHERE email = $1';

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


app.post('/installmentusers', async (req, res) => {
  const {
    firstname,
    lastname, 
    email,
    address,
    province,
    phone,
    name,
    quantity,
    total,
     paymentOption, 
  } = req.body;

    const startDate = new Date();
    startDate.setDate(startDate.getDate() + 7); // Add 7 days to the current date
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + 32); // Add 32 days to the current date

    const formattedStartDate = startDate.toDateString(); // Convert to a readable date format
    const formattedEndDate = endDate.toDateString(); // Convert to a readable date format

   const user = await pool.query('SELECT status FROM installmentusers WHERE email = $1 ORDER BY checkout_date DESC LIMIT 1', [email]);

    if (user.rows.length > 0) {
      const lastStatus = user.rows[0].status;
      if (lastStatus === 'pending') {
        return res.status(400).json({ error: 'You cannot submit the form while your application is pending.' });
      }
    }

    if (total < 500){
      return res.status(500).json({error:'You cannot avail installemnt payment option if your total purchases is below 500'});
    }

  try {
    // Start a database transaction
    await db.transaction(async (trx) => {
      // Generate the order number
      const orderNumber = generateOrderNumber();

      // Insert data into the 'checkout' table, including the order number and new fields
      const insertedOrder = await trx('installmentusers')
        .insert({
          firstname, 
          lastname, 
          email,
          address,
          province,
          phone,
          checkout_date: new Date(),
          name,
          quantity,
          total,  
          order_number: orderNumber,
          payment_option: paymentOption,
          status:'pending',
        })
        .returning('*');

      // Send a success response with the inserted data
      res.json({ success: true, checkoutData: insertedOrder });



        // Send an email with the checkout information to the customer
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
            <p><strong>Payment Method:</strong> ${paymentOption}</p>
            <p>Your first Payment will start on ${formattedStartDate} and ends on ${formattedEndDate}. You will receive an email to notify you of your payment schedule.</p>
          </div>

          <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Shipping Address</h3>

          <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
            <p><strong>Address:</strong> ${address}</p>
            <p><strong>Province:</strong> ${province}</p>
            <p><strong>Phone:</strong> ${phone}</p>
          </div>

          <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at [yeilvastore@gmail.com] or [09497042268]. We're here to help!</p>

          <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>

          <p>Best regards,</p>
          <p>YeilvaSTORE</p>
        </div>
      </body>
    </html>
          `,
        }; 

       
      // Send an email with the checkout information to the admin
const checkoutEmailToAdmin = {
  to: 'ayeilva@yahoo.com',
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
            <p><strong>Total Amount:</strong> ${total}</p>
            <p><strong>Payment Method:</strong> ${paymentOption}</p>
            <p>Your first Payment will start on ${formattedStartDate} and ends on ${formattedEndDate}. You will receive an email to notify you of your payment schedule.</p>
          </div>

          <h3 style="background-color: #f4f4f4; padding: 10px; margin: 0;">Shipping Address</h3>

          <div style="padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px;">
            <p><strong>Address:</strong> ${address}</p>
            <p><strong>Province:</strong> ${province}</p>
            <p><strong>Phone:</strong> ${phone}</p>
          </div>

          <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at [yeilvastore@gmail.com] or [09497042268]. We're here to help!</p>

          <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>

          <p>Best regards,</p>
          <p>YeilvaSTORE</p>
        </div>
      </body>
    </html>
  `,
};


       try {
  // Send checkout info email to customer
  await sgMail.send(checkoutEmailToCustomer);
  // Send checkout info email to admin
  await sgMail.send(checkoutEmailToAdmin);
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
    console.log('Received request for user email:', userEmail); // Add this line for debugging

   const query = 'SELECT firstname, lastname, email, TO_CHAR(timestamp, \'YYYY-MM-DD\') AS joineddate FROM users WHERE email = $1';

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
    from: 'yeilvastore@gmail.com', // Replace with your verified sender email on SendGrid
    subject: 'Password Reset OTP',
    text: `Your OTP is: ${otp}`,
  };

  try {
    await sgMail.send(msg);
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



app.post('/api/saveLoanForm', upload.single('image'), async (req, res) => {
  try {
    const { loanAmount, firstName, lastName, email, phone, gcash, address } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const params = {
      Bucket: BucketName,
      Key: req.file.originalname,
      Body: req.file.buffer,
      ContentType: req.file.mimetype,
    };

    const imageUrl = `https://${params.Bucket}.s3.amazonaws.com/${params.Key}`;

    const user = await pool.query('SELECT status FROM loanusers WHERE email = $1 ORDER BY created_at DESC LIMIT 1', [email]);

    if (user.rows.length > 0) {
      const lastStatus = user.rows[0].status;
      if (lastStatus === 'pending') {
        return res.status(400).json({ error: 'You cannot submit the form while your application is pending.' });
      }
    }

    const applicationNumber = generateApplicationNumber();

    const result = await pool.query(
      'INSERT INTO loanusers (loan_amount, first_name, last_name, email, phone_number, gcash_account, address, created_at, application_number, image, status) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, $8, $9, $10) RETURNING id',
      [loanAmount, firstName, lastName, email, phone, gcash, address, applicationNumber, imageUrl, 'pending']
    );

    const userId = result.rows[0].id;

    await sendLoanApplicationEmail(req, res, email, loanAmount, firstName, lastName, phone, gcash, address, imageUrl);

    res.status(200).json({ userId, applicationNumber });
  } catch (error) {
    console.error('Error saving loan form:', error);
    res.status(500).json({ error: 'An error occurred while processing the loan application' });
  }
});

async function sendLoanApplicationEmail(req, res, email, loanAmount, firstName, lastName, phone, gcash, address, imageUrl) {
  const sendGridApiKey = process.env.SENDGRID_API_KEY;
  const sendGridEndpoint = 'https://api.sendgrid.com/v3/mail/send';

  const imageBuffer = req.file.buffer;
  const imageBase64 = imageBuffer.toString('base64');

  const sendGridData = {
    personalizations: [
      {
        to: [{ email: 'ayeilva@yahoo.com' }],
        subject: 'New Loan Application',
      },
    ],
    from: { email: 'yeilvastore@gmail.com' },
    content: [
      {
        type: 'text/plain',
        value: `New loan application received!\n\nDetails:\nLoan Amount: ₱${loanAmount}\nName: ${firstName} ${lastName}\nEmail: ${email}\nPhone: ${phone}\nGcash Account: ${gcash}\nAddress: ${address}`,
      },
    ],
    attachments: [
      {
        content: imageBase64,
        filename: 'uploaded_image.jpg',
        type: 'image/jpeg',
        disposition: 'attachment',
      },
    ],
  };

  try {
    await axios.post(sendGridEndpoint, sendGridData, {
      headers: {
        Authorization: `Bearer ${sendGridApiKey}`,
        'Content-Type': 'application/json',
      },
    });
    console.log('Loan application email sent successfully');
  } catch (error) {
    console.error('Error sending loan application email:', error);
    res.status(500).json({ error: 'Failed to send loan application email' });
  }
}



app.get('/api/loandata', async (req, res) => {
  try {
    const userEmail = req.query.email;
    console.log('Received request for user email:', userEmail); // Add this line for debugging

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
  .select(' name', 'checkout_date', 'total', 'order_number')
  .from('checkout')
  .where('email', userEmail.replace(/"/g, ''));  // Remove extra quotes here


const query = db
  .select('name', 'checkout_date', 'total', 'order_number')
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


app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://yeilva-store.up.railway.app');
  res.header('Access-Control-Allow-Credentials', true);
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
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
       // Log the token before setting it as a cookie
      // console.log('JWT Token:', token);

      // // Set the token as an HTTP-only cookie if in localhost set secure to false
      //  res.cookie('jwtToken', token, {
      //   httpOnly: true,
      //  secure: false, // Use true for production, false for localhost
      //   sameSite: 'None',
      //   expiresIn: 3600000,
      //   path: '/',
      //   domain: 'localhost',
      // });
        res.cookie('jwtToken', token,{ httpOnly: true});
       res.cookie('cherry','red');

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

// Schedule the deletion job to run every 30 minutes
cron.schedule('*/30 * * * *', async () => {
  try {
    // Perform the deletion process
    const deleteQuery = 'DELETE FROM users WHERE verified = false AND timestamp < $1';
    const thirtyMinutesAgo = new Date(Date.now() - 30 * 60000);
    await pool.query(deleteQuery, [thirtyMinutesAgo]);
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
    console.log('Received review:', reviewData);
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
  
  console.log('Received parameters:', { userEmail, productName });
  
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
        from: 'yeilvastore@gmail.com', // Use your verified SendGrid sender email
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
                    <p><a href="https://yeilva-store.up.railway.app" target="_blank" rel="noopener noreferrer">Shop Now</a></p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 Yeilva Store. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>`,
    };

    try {
        await sgMail.send(msg);
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
    }
};


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
