const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt-nodejs');
const crypto =require('crypto');
const cors = require('cors');
const knex = require('knex');
const nodemailer = require('nodemailer');
const sgMail = require('@sendgrid/mail');
const { Pool } = require('pg');
require('dotenv').config({ path: 'sendgrid.env' });



const db = knex({
 
  connection: {
    host: 'containers-us-west-193.railway.app',
    port: 5925,
    user: 'postgres',
    password: 'V7WT89pgAPCjTEo9OlQC',
    database: 'railway',
  },
});

const pool = new Pool({
  host: 'containers-us-west-193.railway.app',
    port:  5925,
    user: 'postgres',
    password: 'V7WT89pgAPCjTEo9OlQC',
    database: 'railway',
  
});



const app = express();
app.use(express.json());

// Middleware
app.use(bodyParser.json());
app.use(cors());

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
sgMail.setApiKey(SENDGRID_API_KEY);


// Routes
app.get('/', (req, res) => {
  res.send('This is working');
});

app.post('/signin', (req, res) => {
  const { email, password } = req.body;

  // Check if the email exists in the 'users' table
  db.select('email', 'password', 'verified') // Include the 'verified' column in the query
    .from('users')
    .where('email', '=', email)
    .then((data) => {
      if (data.length === 0) {
        res.status(400).json({ error: 'Invalid credentials' }); // Return an error object
      } else {
        // Check if the user is verified
        if (!data[0].verified) {
          return res.status(400).json({ error: 'Email not verified. Please check your email for verification instructions.' });
        }

        // Compare the hashed password
        const isValid = bcrypt.compareSync(password, data[0].password);
        if (isValid) {
          // Return an object with both 'status' and 'email'
          res.json({ status: 'success', email: email });
        } else {
          res.status(400).json({ error: 'Invalid credentials' }); // Return an error object
        }
      }
    })
    .catch((err) => {
      console.error('Error during login:', err);
      res.status(500).json({ error: 'An error occurred during login' }); // Return an error object
    });
});


function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

app.post('/register', async (req, res) => {
  const { email, firstname, lastname, password } = req.body;
  console.log('Request body:', req.body);

  const hash = bcrypt.hashSync(password);

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

    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Error during email confirmation', error);
    res.status(500).json('An error occurred during email confirmation');
  }
});





app.post('/checkout', async (req, res) => {
  const {
    address,
    province,
    phone,
    creditCard,
    email,
    name,
    quantity,
    total,
    cartItems,
  } = req.body;

  try {
    // Start a database transaction
    await db.transaction(async (trx) => {
      // Generate the order number
      const orderNumber = generateOrderNumber();

      // Insert data into the 'checkout' table, including the order number
      const insertedOrder = await trx('checkout')
        .insert({
          address,
          province,
          phone,
          card_no: creditCard,
          checkout_date: new Date(),
          email,
          name,
          quantity,
          total,
          order_number: orderNumber,
        })
        .returning('*');

      // Send a success response with the inserted data
      res.json({ success: true, checkoutData: insertedOrder });

      // Retrieve the user's first name and last name from the 'users' table
      const userData = await trx
        .select('firstname', 'lastname')
        .from('users')
        .where('email', '=', email)
        .first();

      if (!userData) {
        console.error('User data not found for email:', email);
        return;
      }

      const { firstname, lastname } = userData;


        // Send an email with the checkout information to the customer
        const checkoutInfoEmailToCustomer = {
          to: email,
          from: 'yeilvastore@gmail.com',
          subject: 'Checkout Information',
          html: `
            <html>
              <body>
               <h1>Thank You for Your Order!</h1>
    
              <p>Dear ${firstname} ${lastname},</p>
              
              <p>We wanted to express our heartfelt thanks for choosing YeilvaSTORE for your recent purchase. Your order # ${orderNumber} has been received and is now being processed.</p>

              <p>Here are some details about your order:</p>

                   ${name}

              <p>Total Amount: ${total}</p>

              <p>Shipping Address:</p> 
      
                <p>Address: ${address}</p>
                <p>Province: ${province}</p>
                <p>Phone: ${phone}</p>
                <p>Credit Card: ${creditCard}</p>
               
                <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at [yeilvastore@gmail.com] or [09497042268]. We're here to help!</p>

                <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>

                <p>Best regards,</p>
                <p>YeilvaSTORE</p>
                
                <!-- Include other checkout details here -->
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
                 <h1>Thank You for Your Order!</h1>
    
              <p>Dear ${firstname} ${lastname},</p>
              
              <p>We wanted to express our heartfelt thanks for choosing YeilvaSTORE for your recent purchase. Your order # ${orderNumber} has been received and is now being processed.</p>

              <p>Here are some details about your order:</p>

                   ${name}

              <p>Total Amount: ${total}</p>

              <p>Shipping Address:</p> 
      
                <p>Address: ${address}</p>
                <p>Province: ${province}</p>
                <p>Phone: ${phone}</p>
                <p>Credit Card: ${creditCard}</p>
               
                <p>If you have any questions or need further assistance, please don't hesitate to reach out to our customer support team at [yeilvastore@gmail.com] or [09497042268]. We're here to help!</p>

                <p>Thank you again for choosing YeilvaSTORE. We appreciate your business and look forward to serving you in the future.</p>

                <p>Best regards,</p>
                <p>YeilvaSTORE</p>
                <!-- Include other checkout details here -->
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

    const query = 'SELECT firstname, lastname, email FROM users WHERE email = $1';
    const result = await pool.query(query, [userEmail]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    return res.json(user);
  } catch (error) {
    console.error('Error executing SQL query:', error); // Log the SQL query error
    return res.status(500).json({ error: 'Internal server error' });
  }
});



const PORT = process.env.SERVER_PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
