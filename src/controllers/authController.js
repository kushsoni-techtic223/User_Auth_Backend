const authService = require('../services/authService');
const {
  setRefreshCookie,
  clearRefreshCookie,
  readRefreshToken,
} = require('../utils/cookies');

async function register(req, res, next) {
  try {
    const result = await authService.register(req.validated, req);
    res.status(201).json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const result = await authService.login(req.validated, req);
    setRefreshCookie(res, result.refreshToken);
    res.json({
      status: 'success',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        refreshTokenExpiresAt: result.refreshTokenExpiresAt,
      },
    });
  } catch (err) {
    next(err);
  }
}

function refresh(req, res, next) {
  try {
    const token = readRefreshToken(req);
    const result = authService.refresh(token, req);
    setRefreshCookie(res, result.refreshToken);
    res.json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

function logout(req, res, next) {
  try {
    const token = readRefreshToken(req);
    const result = authService.logout(token, req);
    clearRefreshCookie(res);
    res.json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

function logoutAll(req, res, next) {
  try {
    const result = authService.logoutAll(req.user.id, req);
    clearRefreshCookie(res);
    res.json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

function verifyEmail(req, res, next) {
  try {
    const result = authService.verifyEmail(req.validated.token, req);
    res.json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

function requestPasswordReset(req, res, next) {
  try {
    const result = authService.requestPasswordReset(req.validated.email, req);
    res.json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

async function resetPassword(req, res, next) {
  try {
    const result = await authService.resetPassword(req.validated, req);
    clearRefreshCookie(res);
    res.json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

async function changePassword(req, res, next) {
  try {
    const result = await authService.changePassword(req.user.id, req.validated, req);
    clearRefreshCookie(res);
    res.json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

function me(req, res, next) {
  try {
    const user = authService.getMe(req.user.id);
    res.json({ status: 'success', data: { user } });
  } catch (err) {
    next(err);
  }
}

function updateConsent(req, res, next) {
  try {
    const user = authService.updateConsent(
      req.user.id,
      req.validated.consentMarketing,
      req
    );
    res.json({ status: 'success', data: { user } });
  } catch (err) {
    next(err);
  }
}

function exportData(req, res, next) {
  try {
    const data = authService.exportMyData(req.user.id, req);
    res.json({ status: 'success', data });
  } catch (err) {
    next(err);
  }
}

function deleteAccount(req, res, next) {
  try {
    const result = authService.deleteMyAccount(req.user.id, req);
    clearRefreshCookie(res);
    res.json({ status: 'success', data: result });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  register,
  login,
  refresh,
  logout,
  logoutAll,
  verifyEmail,
  requestPasswordReset,
  resetPassword,
  changePassword,
  me,
  updateConsent,
  exportData,
  deleteAccount,
};
