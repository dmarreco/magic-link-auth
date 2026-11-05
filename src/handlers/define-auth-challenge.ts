/* eslint-disable no-param-reassign */
import { DefineAuthChallengeTriggerEvent, DefineAuthChallengeTriggerHandler } from 'aws-lambda';
import { get } from 'env-var';
import { OtpTokenRepository } from '../adapters/otp-token.repository';

import { logger } from '../adapters/logger';

const otpTokenRepo = new OtpTokenRepository(get('OTP_TOKEN_TABLE').required().asString());

export const handler: DefineAuthChallengeTriggerHandler = async (
  event: DefineAuthChallengeTriggerEvent,
): Promise<DefineAuthChallengeTriggerEvent> => {
  try {
    logger.info('DEFINE AUTH CHALLENGE EVENT REQUEST', { event });

    if (event.request.userNotFound) {
      event.response.issueTokens = false;
      event.response.failAuthentication = true;

      logger.info('Failed authentication because userNotFound = true', { event });

      return event;
    }

    if (event.request.session == null || event.request.session.length === 0) {
      // Issue new challenge
      event.response.issueTokens = false;
      event.response.failAuthentication = false;
      event.response.challengeName = 'CUSTOM_CHALLENGE';
    } else {
      const lastAttempt = event.request.session[event.request.session.length - 1];

      const isLastAttemptSuccessful = lastAttempt?.challengeResult === true;

      event.response.issueTokens = isLastAttemptSuccessful;
      event.response.failAuthentication = !isLastAttemptSuccessful;

      if (isLastAttemptSuccessful) {
        const { email } = event.request.userAttributes;

        if (email == null) {
          logger.error('Unexpected event format: there is no user email');
        } else {
          const deleteTokenResult = await otpTokenRepo.delete(email);

          if (deleteTokenResult.isErr())
            logger.error('There was an error trying to invalidate used otp token', {
              event,
              error: deleteTokenResult.error,
            });
        }
      }
    }

    logger.info('DEFINE AUTH CHALLENGE EVENT RESPONSE', { event });

    return event;
  } catch (error) {
    logger.error('DEFINE AUTH CHALLENGE ERROR', { event, error });
    throw error;
  }
};
