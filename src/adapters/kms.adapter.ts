import { DecryptCommand, EncryptCommand, KMSClient, KMSClientConfig } from '@aws-sdk/client-kms';
import { fromPromise } from 'neverthrow';

import { ResultPromise } from './result';

export class KmsAdapter {
  private readonly kmsClient: KMSClient;

  constructor(
    private readonly kmsKeyId: string,
    config: KMSClientConfig = {},
  ) {
    this.kmsClient = new KMSClient(config);
  }

  async encrypt(input: Uint8Array | undefined): ResultPromise<Uint8Array | undefined, Error> {
    const command = new EncryptCommand({ KeyId: this.kmsKeyId, Plaintext: input });

    return fromPromise(
      (async (): Promise<Uint8Array | undefined> =>
        (await this.kmsClient.send(command)).CiphertextBlob)(),
      (error) => error as Error,
    );
  }

  async decrypt(input: Uint8Array | undefined): ResultPromise<Uint8Array | undefined, Error> {
    const command = new DecryptCommand({ CiphertextBlob: input, KeyId: this.kmsKeyId });

    return fromPromise(
      (async (): Promise<Uint8Array | undefined> => (await this.kmsClient.send(command)).Plaintext)(),
      (error) => error as Error,
    );
  }
}
