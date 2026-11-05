import { GetCommand } from '@aws-sdk/lib-dynamodb';
import { err, fromPromise, ok } from 'neverthrow';

import { awsDocumentClient } from './dynamo-client';
import { NotFoundException, ResultPromise } from './result';

export enum UserStatus {
  Pending = 'pending',
  Active = 'active',
  Inactive = 'inactive',
}

export interface UserRecord {
  id: string;
  email: string;
  status: UserStatus;
}

/**
 * Reduced from the monorepo UserRepository (dynamodb-onetable). Keeps the same single-table
 * layout: USEREMAIL#<email> -> { userId }, then USER#<id> -> user item.
 */
export class UserRepository {
  private readonly dynamoDb = awsDocumentClient;

  constructor(private readonly tableName: string) {}

  async findOneByEmail(email: string): ResultPromise<UserRecord, NotFoundException | Error> {
    const emailItem = await fromPromise(
      this.dynamoDb.send(
        new GetCommand({
          TableName: this.tableName,
          Key: { PK: `USEREMAIL#${email}`, SK: `USEREMAIL#${email}` },
        }),
      ),
      (error) => error as Error,
    );

    if (emailItem.isErr()) return err(emailItem.error);

    const userId = emailItem.value.Item?.['userId'] as string | undefined;

    if (userId == null) return err(new NotFoundException('User not found'));

    const userItem = await fromPromise(
      this.dynamoDb.send(
        new GetCommand({
          TableName: this.tableName,
          Key: { PK: `USER#${userId}`, SK: `USER#${userId}` },
        }),
      ),
      (error) => error as Error,
    );

    if (userItem.isErr()) return err(userItem.error);

    const item = userItem.value.Item;

    if (item == null) return err(new NotFoundException('User not found'));

    return ok({ id: userId, email: item['email'] as string, status: item['status'] as UserStatus });
  }
}
