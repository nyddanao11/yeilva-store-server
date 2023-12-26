
const sendgrid = require('@sendgrid/mail');
const SENDGRID_API_KEY = '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';


// using Twilio SendGrid's v3 Node.js Library
// https://github.com/sendgrid/sendgrid-nodejs
javascript
const sgMail = require('@sendgrid/mail')
sgMail.setApiKey(process.env.SENDGRID_API_KEY)
const msg = {
  to: 'test@example.com', // Change to your recipient
  from: 'test@example.com', // Change to your verified sender
  subject: 'Sending with SendGrid is Fun',
  text: 'and easy to do anywhere, even with Node.js',
  html: '<strong>and easy to do anywhere, even with Node.js</strong>',
}
sgMail
  .send(msg)
  .then(() => {
    console.log('Email sent')
  })
  .catch((error) => {
    console.error(error)
  })

  
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});














// const sendgrid = require('@sendgrid/mail');


//     const SENDGRID_API_KEY = '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';

//     sendgrid.setApiKey(SENDGRID_API_KEY)

//     const msg = {
//        to: ['bonifacioamoren@gmail.com', 'yeilvastore@gmail.com'],
//      // Change to your recipient
//        from: {
//         name:'Yeilva Store',
//         email:'yeilvastore@gmail.com',
//       },
//      // Change to your verified sender
//        subject: 'Sending with SendGrid Is Fun',
//        text: 'and easy to do anywhere, even with Node.js',
//        html: '<strong>and easy to do anywhere, even with Node.js</strong>',
//     }
//     sendgrid
//        .send(msg)
//        .then((resp) => {
//          console.log('Email sent\n', resp)
//        })
//        .catch((error) => {
//          console.error(error)
//      })