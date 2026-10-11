
# Blog Website

A full-stack blog application built with Node.js, Express.js,
EJS, and MongoDB.

## Features
- User registration and login
- Admin and User roles
- Password hashing
- Create, view, edit, and delete blog posts
- Author-based permissions
- SEO-friendly blog slugs
- Input validation and sanitization
- Session-based authentication
- CSRF protection for state-changing requests
- REST API for viewing blog posts
- MongoDB storage

## Technologies
- Node.js
- Express.js
- EJS
- MongoDB and Mongoose
- HTML and CSS

## Setup

1. Install Node.js.
2. Create a MongoDB database.
3. Copy `.env.example` to `.env`.
4. Add your MongoDB URI, session secret, and admin credentials.
5. Install packages:

   npm install

6. Start the application:

   npm start

7. Open http://localhost:3000

## Security
Never commit real credentials or your `.env` file.
Use HTTPS and strong secrets in production.

## Note
Configure environment variables before starting the app.
Test the application before deploying it publicly.
