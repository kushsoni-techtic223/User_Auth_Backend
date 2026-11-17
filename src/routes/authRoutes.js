const express = require('express');
const { validate } = require('../middleware/validate');
const { authenticate } = require('../middleware/auth');
const { authLimiter, strictAuthLimiter } = require('../middleware/rateLimiters');
const {
  registerSchema,
  loginSchema,
  verifyEmailSchema,
  requestResetSchema,
  resetPasswordSchema,
  changePasswordSchema,
  updateConsentSchema,
} = require('../validators/authSchemas');
const authController = require('../controllers/authController');
const { env } = require('../config/env');

const router = express.Router();

router.get('/privacy-notice', (req, res) => {
  res.json({
    status: 'success',
    data: {
      privacyPolicyVersion: env.privacyPolicyVersion,
      termsVersion: env.termsVersion,
      dataCollected: [
        'email',
        'display name (optional)',
        'password hash (not the password itself)',
        'consent records',
        'security audit events (IP, user-agent)',
        'session metadata',
      ],
      userRights: [
        'access your data (GET /api/auth/me and /api/auth/export)',
        'correct your data (profile/consent endpoints)',
        'withdraw marketing consent',
        'export your data (data portability)',
        'delete your account (right to erasure)',
      ],
      retention: {
        activeAccount: 'kept while the account remains active',
        deletedAccount: 'PII anonymized; security audit logs retained as needed for security/fraud prevention',
        sessions: 'refresh tokens expire and can be revoked anytime',
      },
      note:
        'This notice is a technical summary for developers. Publish a full privacy policy reviewed by counsel for your jurisdictions before production use.',
    },
  });
});

router.post('/register', authLimiter, validate(registerSchema), authController.register);
router.post('/login', authLimiter, validate(loginSchema), authController.login);
router.post('/refresh', authLimiter, authController.refresh);
router.post('/logout', authController.logout);

router.post(
  '/verify-email',
  authLimiter,
  validate(verifyEmailSchema),
  authController.verifyEmail
);

router.post(
  '/forgot-password',
  strictAuthLimiter,
  validate(requestResetSchema),
  authController.requestPasswordReset
);

router.post(
  '/reset-password',
  strictAuthLimiter,
  validate(resetPasswordSchema),
  authController.resetPassword
);

router.get('/me', authenticate, authController.me);
router.post('/logout-all', authenticate, authController.logoutAll);
router.post(
  '/change-password',
  authenticate,
  strictAuthLimiter,
  validate(changePasswordSchema),
  authController.changePassword
);
router.patch(
  '/consent',
  authenticate,
  validate(updateConsentSchema),
  authController.updateConsent
);
router.get('/export', authenticate, authController.exportData);
router.delete('/account', authenticate, strictAuthLimiter, authController.deleteAccount);

module.exports = router;
