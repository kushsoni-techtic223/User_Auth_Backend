const { verifyAccessToken } = require('../utils/crypto');
const userService = require('../services/userService');

function authenticate(req, res, next) {
  const header = req.get('authorization') || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({
      status: 'error',
      code: 'UNAUTHORIZED',
      message: 'Access token required',
    });
  }

  try {
    const payload = verifyAccessToken(token);
    const user = userService.findActiveUserById(payload.sub);

    if (!user || !user.is_active) {
      return res.status(401).json({
        status: 'error',
        code: 'UNAUTHORIZED',
        message: 'Invalid session',
      });
    }

    req.user = userService.toPublicUser(user);
    req.auth = payload;
    return next();
  } catch {
    return res.status(401).json({
      status: 'error',
      code: 'UNAUTHORIZED',
      message: 'Invalid or expired access token',
    });
  }
}

module.exports = { authenticate };
