const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto =require('crypto');
const cors = require('cors');
const knex = require('knex');
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
const sdk = require('api')('@paymongo/v2#gr8xcr81ylnv4k33i');
require('dotenv').config({ path: 'sendgrid.env' });
require('dotenv').config({ path: 'paymongo.env' });
require('dotenv').config({ path: 'tokensecret.env' });
require('dotenv').config({ path: 's3.env' });





const db = knex({
  client: 'pg',
  connection: {
    host: 'roundhouse.proxy.rlwy.net',
    port: 34919,
    user: 'postgres',
    password:'2bb2gbGEgBde16fDF2f1Ac534151cg3a',
    database: 'railway',
  },
});

const pool = new Pool({
   host: 'roundhouse.proxy.rlwy.net',
    port: 34919,
    user: 'postgres',
    password:'2bb2gbGEgBde16fDF2f1Ac534151cg3a',
    database: 'railway',
  
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
  origin: 'https://yeilva-store.up.railway.app/', 
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
      from: 'yeilvastore@gmail.com', // Replace with your email address

      subject: 'Email Verification',
      text: `Click the following link to verify your email: ${verificationLink}`,
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
  } = req.body;

  try {
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
          total,  
          order_number: orderNumber,
          payment_option: paymentOption,
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
  res.header('Access-Control-Allow-Origin', 'https://yeilva-store.up.railway.app/');
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





// Endpoint to create a checkout session
app.post('/create-checkout', (req, res) => {
  sdk.createACheckout({
    data: {
      attributes: { send_email_receipt: false, show_description: true, show_line_items: true }
    }
  })
    .then(({ data }) => res.json(data))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Endpoint to retrieve a checkout session
app.get('/retrieve-checkout/:checkout_session_id', (req, res) => {
  sdk.auth('sk_test_b13vZMxsGY7q8cDsABgkZoEy', '');
  sdk.retrieveACheckout({ checkout_session_id: req.params.checkout_session_id })
    .then(({ data }) => res.json(data))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Endpoint to expire a checkout session
app.put('/expire-checkout/:checkout_session_id', (req, res) => {
  sdk.auth('sk_test_b13vZMxsGY7q8cDsABgkZoEy', '');
  sdk.expireACheckoutSession({ checkout_session_id: req.params.checkout_session_id })
    .then(({ data }) => res.json(data))
    .catch(err => res.status(500).json({ error: err.message }));
});




const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
