import { randomUUID } from 'crypto';

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { z } from 'zod';

import { KmsAdapter } from '../adapters/kms.adapter';
import { logger } from '../adapters/logger';
import { OtpTokenRepository } from '../adapters/otp-token.repository';
import { NotFoundException } from '../adapters/result';
import { EmailBodyFormat, SesAdapter } from '../adapters/ses.adapter';
import { UserRepository, UserStatus } from '../adapters/user.repository';
import { loginNoPwdConfig } from '../config';
import { buildMagicLinkEmail } from '../email/magic-link-email';

export const loginNoPwdSchema = z
  .object({
    email: z
      .string()
      .min(1, { message: 'An email address is required' })
      .max(255, { message: 'An email address cannot be longer than 255 characters' })
      .email('This is not a valid email'),
  })
  .strict();

const noContent = (): APIGatewayProxyResult => ({ statusCode: 204, body: '' });

const badRequest = (message: string): APIGatewayProxyResult => ({
  statusCode: 400,
  body: JSON.stringify({ message }),
});

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  let body: unknown;

  try {
    body = JSON.parse(event.body ?? '{}');
  } catch {
    return badRequest('Invalid JSON body');
  }

  const parsed = loginNoPwdSchema.safeParse(body);

  if (!parsed.success) return badRequest(parsed.error.issues.map((i) => i.message).join('; '));

  const { email } = parsed.data;

  const userRepository = new UserRepository(loginNoPwdConfig.userTableName);
  const otpTokenRepo = new OtpTokenRepository(loginNoPwdConfig.otpTokenTableName);
  const kms = new KmsAdapter(loginNoPwdConfig.kmsKeyId);
  const ses = new SesAdapter();

  const now = new Date();
  const expirationTimeMillis = loginNoPwdConfig.magicLinkExpirationMinutes * 60 * 1000;
  const expiration = new Date(now.getTime() + expirationTimeMillis);
  const payload = {
    email,
    expiration: expiration.toJSON(),
    // expiration is exposed in dynamo for TTL, so add entropy to the payload
    rnd: randomUUID(),
  };

  // (2) check if user exists and is active
  const getUserResult = await userRepository.findOneByEmail(email);

  if (getUserResult.isErr()) {
    if (getUserResult.error instanceof NotFoundException) {
      logger.warn('Someone tried to generate a magic link for an unknown email', { email });

      return noContent();
    }

    logger.error('There was an unexpected error trying to retrieve user by email');
    throw getUserResult.error;
  }

  if (getUserResult.value.status !== UserStatus.Active) {
    logger.warn('Someone tried to generate a magic link for an unactive user email', { email });

    return noContent();
  }

  // (3) encrypt {email, expiration} => token
  const encryptTokenResult = await kms.encrypt(Buffer.from(JSON.stringify(payload)));

  if (encryptTokenResult.isErr()) throw encryptTokenResult.error;

  const tokenB64Url = Buffer.from(encryptTokenResult.value as Uint8Array).toString('base64url');

  // (4) save {email, token}; db TTL is 30 seconds after token expiration
  const saveTokenResult = await otpTokenRepo.save(email, tokenB64Url, expiration.getTime() + 30000);

  if (saveTokenResult.isErr()) throw saveTokenResult.error;

  // (5) send the magic link through SES
  const { emailSubject, emailMessage } = buildMagicLinkEmail(email, tokenB64Url);

  const sesResult = await ses.sendEmail({
    body: emailMessage,
    format: EmailBodyFormat.Html,
    recipientAddress: email,
    subject: emailSubject,
  });

  if (sesResult.isErr()) throw sesResult.error;

  return noContent();
};
