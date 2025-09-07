const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');
const router = express.Router();

// Validation helper functions
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  // At least 6 characters
  return password && password.length >= 6;
};

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) {
    return next();
  } else {
    return res.status(401).json({ 
      message: 'Authentication required',
      loggedIn: false 
    });
  }
};

// Register endpoint
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        message: 'Email and password are required' 
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ 
        message: 'Please enter a valid email address' 
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Check if user already exists
    db.get(
      'SELECT * FROM users WHERE email = ?', 
      [email.toLowerCase()], 
      async (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            message: 'Database error occurred' 
          });
        }

        if (user) {
          return res.status(400).json({ 
            message: 'Email already registered. Please use a different email or try logging in.' 
          });
        }

        try {
          // Hash password
          const saltRounds = 12;
          const hashedPassword = await bcrypt.hash(password, saltRounds);

          // Insert new user
          db.run(
            'INSERT INTO users (email, password) VALUES (?, ?)',
            [email.toLowerCase(), hashedPassword],
            function(err) {
              if (err) {
                console.error('Error inserting user:', err);
                return res.status(500).json({ 
                  message: 'Failed to create account' 
                });
              }

              console.log(`✅ New user registered: ${email} (ID: ${this.lastID})`);
              res.status(201).json({ 
                message: 'Account created successfully! You can now log in.',
                userId: this.lastID
              });
            }
          );
        } catch (hashError) {
          console.error('Error hashing password:', hashError);
          res.status(500).json({ 
            message: 'Failed to create account' 
          });
        }
      }
    );
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      message: 'Server error occurred' 
    });
  }
});

// Login endpoint
router.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        message: 'Email and password are required' 
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ 
        message: 'Please enter a valid email address' 
      });
    }

    // Find user in database
    db.get(
      'SELECT * FROM users WHERE email = ?', 
      [email.toLowerCase()], 
      async (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ 
            message: 'Database error occurred' 
          });
        }

        if (!user) {
          return res.status(401).json({ 
            message: 'Invalid email or password' 
          });
        }

        try {
          // Compare password
          const passwordMatch = await bcrypt.compare(password, user.password);

          if (!passwordMatch) {
            return res.status(401).json({ 
              message: 'Invalid email or password' 
            });
          }

          // Create session
          req.session.userId = user.id;
          req.session.userEmail = user.email;

          console.log(`✅ User logged in: ${user.email} (ID: ${user.id})`);

          res.json({ 
            message: 'Login successful',
            loggedIn: true,
            user: {
              id: user.id,
              email: user.email
            }
          });
        } catch (compareError) {
          console.error('Error comparing password:', compareError);
          res.status(500).json({ 
            message: 'Login failed' 
          });
        }
      }
    );
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      message: 'Server error occurred' 
    });
  }
});

// Check authentication status
router.get('/check', (req, res) => {
  if (req.session && req.session.userId) {
    // Get user details from database
    db.get(
      'SELECT id, email, created_at FROM users WHERE id = ?', 
      [req.session.userId], 
      (err, user) => {
        if (err || !user) {
          // Invalid session, destroy it
          req.session.destroy();
          return res.json({ 
            loggedIn: false 
          });
        }

        res.json({ 
          loggedIn: true,
          user: {
            id: user.id,
            email: user.email,
            createdAt: user.created_at
          }
        });
      }
    );
  } else {
    res.json({ 
      loggedIn: false 
    });
  }
});

// Get user profile (protected route)
router.get('/profile', requireAuth, (req, res) => {
  db.get(
    'SELECT id, email, created_at FROM users WHERE id = ?', 
    [req.session.userId], 
    (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          message: 'Failed to fetch profile' 
        });
      }

      if (!user) {
        return res.status(404).json({ 
          message: 'User not found' 
        });
      }

      res.json({
        user: {
          id: user.id,
          email: user.email,
          createdAt: user.created_at
        }
      });
    }
  );
});

// Logout endpoint
router.post('/logout', (req, res) => {
  const userEmail = req.session.userEmail;
  
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ 
        message: 'Failed to logout' 
      });
    }

    // Clear the session cookie
    res.clearCookie('sessionId');
    
    console.log(`✅ User logged out: ${userEmail || 'Unknown'}`);
    
    res.json({ 
      message: 'Logged out successfully',
      loggedIn: false 
    });
  });
});

// Change password (protected route)
router.post('/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        message: 'Current password and new password are required' 
      });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({ 
        message: 'New password must be at least 6 characters long' 
      });
    }

    // Get current user
    db.get(
      'SELECT * FROM users WHERE id = ?', 
      [req.session.userId], 
      async (err, user) => {
        if (err || !user) {
          return res.status(404).json({ 
            message: 'User not found' 
          });
        }

        try {
          // Verify current password
          const passwordMatch = await bcrypt.compare(currentPassword, user.password);
          
          if (!passwordMatch) {
            return res.status(401).json({ 
              message: 'Current password is incorrect' 
            });
          }

          // Hash new password
          const saltRounds = 12;
          const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

          // Update password in database
          db.run(
            'UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [hashedNewPassword, req.session.userId],
            function(err) {
              if (err) {
                console.error('Error updating password:', err);
                return res.status(500).json({ 
                  message: 'Failed to update password' 
                });
              }

              console.log(`✅ Password changed for user ID: ${req.session.userId}`);
              res.json({ 
                message: 'Password updated successfully' 
              });
            }
          );
        } catch (error) {
          console.error('Error in change password:', error);
          res.status(500).json({ 
            message: 'Failed to update password' 
          });
        }
      }
    );
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ 
      message: 'Server error occurred' 
    });
  }
});

module.exports = router;
