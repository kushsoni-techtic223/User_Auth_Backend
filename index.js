const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const { env } = require('./src/config/env');
require('./src/db/database');

const authRoutes = require('./src/routes/authRoutes');
const { notFoundHandler, errorHandler } = require('./src/middleware/errorHandler');

const app = express();

app.set('trust proxy', 1);

app.use(helmet());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json({ limit: '32kb' }));
app.use(cookieParser());

app.get('/', (req, res) => {
  res.json({
    status: 'success',
    message: 'User Auth Backend',
    docs: {
      privacyNotice: '/api/auth/privacy-notice',
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login',
      me: 'GET /api/auth/me',
    },
  });
});

app.get('/api/status', (req, res) => {
  res.json({ status: 'success', message: 'Server is running smoothly' });
});

app.use('/api/auth', authRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

app.listen(env.port, '0.0.0.0', () => {
  console.log(`Auth server listening on http://localhost:${env.port}`);
  console.log(`LAN devices can reach http://<your-ip>:${env.port}`);
});
