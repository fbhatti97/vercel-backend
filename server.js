// server.js

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const dotenv = require('dotenv');
const { sql } = require('@vercel/postgres');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

// Load environment variables from .env file
dotenv.config();

const app = express();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET;
const pool = new Pool({
    connectionString: process.env.POSTGRES_URL,
  });

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Middleware for checking JWT tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('No token provided');
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification failed:', err);
      return res.sendStatus(403); // Forbidden
    }
    console.log('Token verified, user:', user);
    req.user = user;
    next();
  });
}

// Login Endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: '1h',
    });

    return res.status(200).json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Register Endpoint
app.post('/api/register', async (req, res) => {
  const { firstName, lastName, email, mobileNumber, password, confirmPassword } = req.body;

  if (!firstName || !lastName || !email || !mobileNumber || !password || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  try {
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Email is already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        firstName,
        lastName,
        email,
        mobileNumber,
        password: hashedPassword,
        credits: 0,
      },
    });

    return res.status(201).json(newUser);
  } catch (error) {
    console.error('Error during registration:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// User Details Endpoint
app.post('/api/user/details', async (req, res) => {
    const { token } = req.body;
  
    try {
      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
  
      // Fetch user and claims data using Prisma
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        include: { claims: true }, // Include associated claims
      });
  
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      res.json({ user, claims: user.claims });
    } catch (error) {
      console.error('Error fetching user details:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/api/make-claim', async (req, res) => {
    try {
      const { token, paidCompleteGapFee, amountPaid, status } = req.body;
  
      if (!token) {
        return res.status(400).json({ error: 'Token is missing' });
      }
  
      const decoded = jwt.verify(token, JWT_SECRET);
      const userId = decoded.userId;
  
      await pool.query(
        'INSERT INTO "Claim" ("userId", "paidCompleteGapFee", "amountPaid", "status", "dateOfSubmission") VALUES ($1, $2, $3, $4, NOW())',
        [userId, paidCompleteGapFee, amountPaid, status]
      );
  
      res.status(200).json({ message: 'Claim submitted successfully' });
    } catch (error) {
      console.error('Error during claim submission:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

// Verify Token Endpoint
app.post('/api/verify-token', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token is missing' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await sql`SELECT * FROM "User" WHERE "id" = ${decoded.userId}`;
    const user = result.rows[0];

    if (user) {
      return res.status(200).json(user);
    } else {
      return res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error verifying token:', error);
    return res.status(500).json({ error: error.message || 'Unknown error' });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://localhost:${PORT} and is accessible externally.`);
});
