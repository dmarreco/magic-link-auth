import { get } from 'env-var';

// Lazy so that importing a module does not throw when env is not set (e.g. in other handlers)
export const loginNoPwdConfig = {
  get kmsKeyId(): string {
    return get('KMS_KEY_ID').required().asString();
  },
  get frontendBaseUrl(): string {
    return get('FRONTEND_BASE_URL').required().asString();
  },
  get magicLinkExpirationMinutes(): number {
    return get('MAGIC_LINK_EXPIRATION_MINUTES').default(60).asInt();
  },
  get otpTokenTableName(): string {
    return get('OTP_TOKEN_TABLE').required().asString();
  },
  get userTableName(): string {
    return get('USER_TABLE').required().asString();
  },
};
