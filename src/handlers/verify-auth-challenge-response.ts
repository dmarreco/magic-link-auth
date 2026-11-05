/* eslint-disable no-param-reassign */
import {
  VerifyAuthChallengeResponseTriggerEvent,
  VerifyAuthChallengeResponseTriggerHandler,
} from 'aws-lambda';
import { get } from 'env-var';

import { KmsAdapter } from '../adapters/kms.adapter';
import { logger } from '../adapters/logger';

const kms = new KmsAdapter(get('KMS_KEY_ID').required().asString());

export const handler: VerifyAuthChallengeResponseTriggerHandler = async (
  event: VerifyAuthChallengeResponseTriggerEvent,
): Promise<VerifyAuthChallengeResponseTriggerEvent> => {
  try {
    logger.info('VERIFY AUTH CHALLENGE EVENT REQUEST', { event });

    const { email } = event.request.userAttributes;

    // fail if encrypted tokens do not match
    const expected = event.request.privateChallengeParameters['challenge'];

    if (event.request.challengeAnswer !== expected) {
      logger.info("answer doesn't match current challenge token");

      event.response.answerCorrect = false;

      return event;
    }

    const decryptResult = await kms.decrypt(
      Buffer.from(event.request.challengeAnswer, 'base64url'),
    );

    if (decryptResult.isErr()) throw decryptResult.error;

    const decrypted = decryptResult.value;

    if (decrypted == null) throw new Error('Decrypted data is null');

    const json = Buffer.from(decrypted).toString();
    const payload = JSON.parse(json);

    const isExpired = new Date().toJSON() > payload.expiration;

    logger.info('Payload decrypted', { payload });

    if (payload.email === email && !isExpired) {
      event.response.answerCorrect = true;
    } else {
      logger.info("email doesn't match or token is expired");
      event.response.answerCorrect = false;
    }

    logger.info('VERIFY AUTH CHALLENGE RESPONSE', { event });

    return event;
  } catch (error) {
    logger.error('VERIFY AUTH CHALLENGE RESPONSE ERROR', { event, error });
    throw error;
  }
};
