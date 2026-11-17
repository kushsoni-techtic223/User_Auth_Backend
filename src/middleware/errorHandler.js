const { AuthError } = require('../services/authService');
const { env } = require('../config/env');

function notFoundHandler(req, res) {
  res.status(404).json({
    status: 'error',
    code: 'NOT_FOUND',
    message: `Route ${req.method} ${req.path} not found`,
  });
}

function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    return next(err);
  }

  if (err instanceof AuthError) {
    return res.status(err.statusCode).json({
      status: 'error',
      code: err.code,
      message: err.message,
    });
  }

  console.error('[error]', err);

  return res.status(500).json({
    status: 'error',
    code: 'INTERNAL_ERROR',
    message: env.isProd ? 'Something went wrong' : err.message,
  });
}

module.exports = { notFoundHandler, errorHandler };
