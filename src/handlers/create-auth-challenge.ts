/* eslint-disable no-param-reassign */
import { CreateAuthChallengeTriggerEvent, CreateAuthChallengeTriggerHandler } from 'aws-lambda';
import { get } from 'env-var';
import { OtpTokenRepository } from '../adapters/otp-token.repository';

import { logger } from '../adapters/logger';

const otpTokenRepo = new OtpTokenRepository(get('OTP_TOKEN_TABLE').required().asString());

export const handler: CreateAuthChallengeTriggerHandler = async (
  event: CreateAuthChallengeTriggerEvent,
): Promise<CreateAuthChallengeTriggerEvent> => {
  try {
    logger.info('CREATE AUTH CHALLENGE EVENT REQUEST', { event });

    const email = event.request.userAttributes['email'] as string;

    event.response.publicChallengeParameters = { email };

    logger.debug('Retrieving persisted token');

    const token = await otpTokenRepo.getOtpTokenByEmail(email);

    if (token.isErr()) throw token.error;
    
    if (token.value == null) {
      logger.info('No persisted token found for email (token has been expired and removed from table?)');
    }

    // the verify step would decrypt this and check the user's answer
    event.response.privateChallengeParameters = {
      challenge: token.value == null ? '#EXPIRED' : token.value,
    };

    logger.info('CREATE AUTH CHALLENGE EVENT RESPONSE', { event });

    return event;
  } catch (error) {
    logger.error('CREATE AUTH CHALLENGE ERROR', { event, error });
    throw error;
  }
};
