import { DeleteCommand, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { err, fromPromise, ok } from 'neverthrow';

import { awsDocumentClient } from './dynamo-client';
import { logger } from './logger';
import { ResultPromise } from './result';

export class InvalidTtlTimestampGranularityError extends Error {
  constructor() {
    super('TTL must be expressed in epoch milliseconds');
    this.name = 'InvalidTtlTimestampGranularityError';
  }
}

export class OtpTokenRepository {
  private readonly dynamoDb = awsDocumentClient;

  constructor(private readonly tableName: string) {}

  private key(email: string): { PK: string; SK: string } {
    return { PK: `EMAIL#${email}`, SK: `EMAIL#${email}` };
  }

  async getOtpTokenByEmail(email: string): ResultPromise<string | null, Error> {
    const params = { TableName: this.tableName, Key: this.key(email) };

    logger.debug('Dynamodb getItem request', { params });

    const result = await fromPromise(
      this.dynamoDb.send(new GetCommand(params)),
      (error) => error as Error,
    );

    if (result.isErr()) return err(result.error);

    if (result.value.Item == null) return ok(null);

    return ok(result.value.Item['token'] as string);
  }

  async delete(email: string): ResultPromise<null, Error> {
    const params = { TableName: this.tableName, Key: this.key(email) };

    return fromPromise(
      (async (): Promise<null> => {
        await this.dynamoDb.send(new DeleteCommand(params));

        return null;
      })(),
      (error) => error as Error,
    );
  }

  async save(
    email: string,
    token: string,
    ttlExpirationMillis: number,
  ): ResultPromise<null, Error> {
    if (ttlExpirationMillis <= 99999999999) {
      return err(new InvalidTtlTimestampGranularityError());
    }

    const params = {
      TableName: this.tableName,
      Item: {
        ...this.key(email),
        email,
        token,
        ttlExpiration: Math.floor(ttlExpirationMillis / 1000),
      },
    };

    const result = await fromPromise(
      this.dynamoDb.send(new PutCommand(params)),
      (error) => error as Error,
    );

    if (result.isErr()) return err(result.error);

    return ok(null);
  }
}
