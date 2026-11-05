import { EncryptCommand } from '@aws-sdk/client-kms';
import { SendEmailCommand } from '@aws-sdk/client-ses';
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { APIGatewayProxyEvent } from 'aws-lambda';

import { awsDocumentClient } from '../../src/adapters/dynamo-client';
import { handler } from '../../src/handlers/login-no-pwd';

const { KMSClient } = jest.requireActual('@aws-sdk/client-kms');
const { SESClient } = jest.requireActual('@aws-sdk/client-ses');

const ddb = mockClient(awsDocumentClient);
const kms = mockClient(KMSClient);
const ses = mockClient(SESClient);

const call = (body: unknown): Promise<{ statusCode: number; body: string }> =>
  handler({ body: typeof body === 'string' ? body : JSON.stringify(body) } as APIGatewayProxyEvent);

const mockUser = (status: string | null): void => {
  ddb.on(GetCommand, { Key: { PK: 'USEREMAIL#a@b.com', SK: 'USEREMAIL#a@b.com' } }).resolves(
    status == null ? {} : { Item: { userId: 'u1' } },
  );
  ddb
    .on(GetCommand, { Key: { PK: 'USER#u1', SK: 'USER#u1' } })
    .resolves({ Item: { email: 'a@b.com', status } });
};

beforeEach(() => {
  ddb.reset();
  kms.reset();
  ses.reset();
});

describe('login-no-pwd handler', () => {
  it('returns 400 for invalid body', async () => {
    expect((await call('not json')).statusCode).toBe(400);
    expect((await call({ email: 'nope' })).statusCode).toBe(400);
    expect((await call({ email: 'a@b.com', extra: 1 })).statusCode).toBe(400);
  });

  it('returns 204 and sends nothing for an unknown email', async () => {
    mockUser(null);
    expect((await call({ email: 'a@b.com' })).statusCode).toBe(204);
    expect(kms.commandCalls(EncryptCommand)).toHaveLength(0);
    expect(ses.commandCalls(SendEmailCommand)).toHaveLength(0);
  });

  it('returns 204 and sends nothing for an inactive user', async () => {
    mockUser('inactive');
    expect((await call({ email: 'a@b.com' })).statusCode).toBe(204);
    expect(ses.commandCalls(SendEmailCommand)).toHaveLength(0);
  });

  it('encrypts, stores the token and emails the magic link for an active user', async () => {
    mockUser('active');
    kms.on(EncryptCommand).resolves({ CiphertextBlob: Buffer.from('cipher') });
    ddb.on(PutCommand).resolves({});
    ses.on(SendEmailCommand).resolves({ MessageId: 'm1' });

    const res = await call({ email: 'a@b.com' });

    expect(res.statusCode).toBe(204);
    const token = Buffer.from('cipher').toString('base64url');

    const plaintext = JSON.parse(
      Buffer.from(kms.commandCalls(EncryptCommand)[0]?.args[0].input.Plaintext as Uint8Array).toString(),
    );
    expect(plaintext.email).toBe('a@b.com');
    expect(new Date(plaintext.expiration).getTime()).toBeGreaterThan(Date.now());

    const put = ddb.commandCalls(PutCommand)[0]?.args[0].input;
    expect(put?.TableName).toBe('test-otp-table');
    expect(put?.Item).toMatchObject({ PK: 'EMAIL#a@b.com', email: 'a@b.com', token });
    // ttl is in epoch seconds, 30s after expiration
    expect(put?.Item?.['ttlExpiration']).toBeGreaterThan(Date.now() / 1000);

    const sent = ses.commandCalls(SendEmailCommand)[0]?.args[0].input;
    expect(sent?.Destination?.ToAddresses).toEqual(['a@b.com']);
    expect(sent?.Message?.Body?.Html?.Data).toContain(
      `https://app.example.test/magic-link?token=${token}&email=a@b.com`,
    );
  });

  it('propagates SES failures', async () => {
    mockUser('active');
    kms.on(EncryptCommand).resolves({ CiphertextBlob: Buffer.from('cipher') });
    ddb.on(PutCommand).resolves({});
    ses.on(SendEmailCommand).rejects(new Error('ses down'));
    await expect(call({ email: 'a@b.com' })).rejects.toThrow('ses down');
  });
});
