import { DeleteCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { DecryptCommand } from '@aws-sdk/client-kms';
import { mockClient } from 'aws-sdk-client-mock';
import { CreateAuthChallengeTriggerEvent, DefineAuthChallengeTriggerEvent, VerifyAuthChallengeResponseTriggerEvent } from 'aws-lambda';

import { awsDocumentClient } from '../../src/adapters/dynamo-client';
import { handler as createHandler } from '../../src/handlers/create-auth-challenge';
import { handler as defineHandler } from '../../src/handlers/define-auth-challenge';
import { handler as verifyHandler } from '../../src/handlers/verify-auth-challenge-response';

const ddb = mockClient(awsDocumentClient);

const asEvent = <T>(e: unknown): T => e as T;
const noCtx = {} as never;
const noCb = (() => undefined) as never;

beforeEach(() => ddb.reset());

describe('define-auth-challenge', () => {
  const base = (over: object): DefineAuthChallengeTriggerEvent =>
    asEvent({ request: { userAttributes: { email: 'a@b.com' }, session: [] }, response: {}, ...over });

  it('fails authentication when user not found', async () => {
    const e = base({ request: { userNotFound: true, userAttributes: {}, session: [] } });
    const res = (await defineHandler(e, noCtx, noCb)) as DefineAuthChallengeTriggerEvent;
    expect(res.response).toMatchObject({ issueTokens: false, failAuthentication: true });
  });

  it('issues a custom challenge on first attempt', async () => {
    const res = (await defineHandler(base({}), noCtx, noCb)) as DefineAuthChallengeTriggerEvent;
    expect(res.response).toMatchObject({
      issueTokens: false,
      failAuthentication: false,
      challengeName: 'CUSTOM_CHALLENGE',
    });
  });

  it('issues tokens and deletes the otp token on success', async () => {
    ddb.on(DeleteCommand).resolves({});
    const e = base({
      request: { userAttributes: { email: 'a@b.com' }, session: [{ challengeResult: true }] },
    });
    const res = (await defineHandler(e, noCtx, noCb)) as DefineAuthChallengeTriggerEvent;
    expect(res.response).toMatchObject({ issueTokens: true, failAuthentication: false });
    expect(ddb.commandCalls(DeleteCommand)[0]?.args[0].input.Key).toEqual({
      PK: 'EMAIL#a@b.com',
      SK: 'EMAIL#a@b.com',
    });
  });

  it('fails authentication when the last attempt failed', async () => {
    const e = base({
      request: { userAttributes: { email: 'a@b.com' }, session: [{ challengeResult: false }] },
    });
    const res = (await defineHandler(e, noCtx, noCb)) as DefineAuthChallengeTriggerEvent;
    expect(res.response).toMatchObject({ issueTokens: false, failAuthentication: true });
    expect(ddb.commandCalls(DeleteCommand)).toHaveLength(0);
  });
});

describe('create-auth-challenge', () => {
  const event = asEvent<CreateAuthChallengeTriggerEvent>({
    request: { userAttributes: { email: 'a@b.com' } },
    response: {},
  });

  it('puts the persisted token in the private challenge parameters', async () => {
    ddb.on(GetCommand).resolves({ Item: { token: 'tok123' } });
    const res = (await createHandler(structuredClone(event), noCtx, noCb)) as CreateAuthChallengeTriggerEvent;
    expect(res.response.publicChallengeParameters).toEqual({ email: 'a@b.com' });
    expect(res.response.privateChallengeParameters).toEqual({ challenge: 'tok123' });
  });

  it('uses #EXPIRED when no token is persisted', async () => {
    ddb.on(GetCommand).resolves({});
    const res = (await createHandler(structuredClone(event), noCtx, noCb)) as CreateAuthChallengeTriggerEvent;
    expect(res.response.privateChallengeParameters).toEqual({ challenge: '#EXPIRED' });
  });
});

describe('verify-auth-challenge-response', () => {
  // The KMS client is created inside the adapter; mock at the SDK send prototype level.
  const { KMSClient } = jest.requireActual('@aws-sdk/client-kms');
  const kms = mockClient(KMSClient);
  const token = Buffer.from('cipher').toString('base64url');

  const evt = (answer: string, challenge = token) =>
    asEvent<VerifyAuthChallengeResponseTriggerEvent>({
      request: {
        userAttributes: { email: 'a@b.com' },
        privateChallengeParameters: { challenge },
        challengeAnswer: answer,
      },
      response: {},
    });

  const plaintext = (email: string, expiration: Date): Uint8Array =>
    Buffer.from(JSON.stringify({ email, expiration: expiration.toJSON(), rnd: 'x' }));

  beforeEach(() => kms.reset());

  it('rejects an answer that differs from the stored challenge', async () => {
    const res = (await verifyHandler(evt('other'), noCtx, noCb)) as VerifyAuthChallengeResponseTriggerEvent;
    expect(res.response.answerCorrect).toBe(false);
    expect(kms.commandCalls(DecryptCommand)).toHaveLength(0);
  });

  it('accepts a valid, unexpired token for the same email', async () => {
    kms.on(DecryptCommand).resolves({ Plaintext: plaintext('a@b.com', new Date(Date.now() + 60000)) });
    const res = (await verifyHandler(evt(token), noCtx, noCb)) as VerifyAuthChallengeResponseTriggerEvent;
    expect(res.response.answerCorrect).toBe(true);
  });

  it('rejects a token for a different email', async () => {
    kms.on(DecryptCommand).resolves({ Plaintext: plaintext('x@y.com', new Date(Date.now() + 60000)) });
    const res = (await verifyHandler(evt(token), noCtx, noCb)) as VerifyAuthChallengeResponseTriggerEvent;
    expect(res.response.answerCorrect).toBe(false);
  });

  it('rejects an expired token', async () => {
    kms.on(DecryptCommand).resolves({ Plaintext: plaintext('a@b.com', new Date(Date.now() - 1000)) });
    const res = (await verifyHandler(evt(token), noCtx, noCb)) as VerifyAuthChallengeResponseTriggerEvent;
    expect(res.response.answerCorrect).toBe(false);
  });
});
