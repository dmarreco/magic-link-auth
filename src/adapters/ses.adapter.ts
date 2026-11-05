import { SESClient, SESClientConfig, SendEmailCommand } from '@aws-sdk/client-ses';
import { fromPromise } from 'neverthrow';

import { ResultPromise } from './result';

const SENDER_EMAIL = 'no-reply@gethomecloud.com';

export enum EmailBodyFormat {
  PlainText = 'plain-text',
  Html = 'html',
}

export interface OutgoingEmailMessage {
  subject: string;
  body: string;
  format: EmailBodyFormat;
  recipientAddress: string;
}

const mapSesBodyAttributeName: Record<EmailBodyFormat, string> = {
  [EmailBodyFormat.Html]: 'Html',
  [EmailBodyFormat.PlainText]: 'Text',
};

export class SesAdapter {
  private readonly sesClient: SESClient;

  constructor(cfg: SESClientConfig = {}) {
    this.sesClient = new SESClient(cfg);
  }

  async sendEmail(mailMessage: OutgoingEmailMessage): ResultPromise<string | undefined, Error> {
    const params = {
      Source: SENDER_EMAIL,
      Destination: { ToAddresses: [mailMessage.recipientAddress] },
      Message: {
        Subject: { Data: mailMessage.subject, Charset: 'UTF-8' },
        Body: {
          [mapSesBodyAttributeName[mailMessage.format]]: {
            Data: mailMessage.body,
            Charset: 'UTF-8',
          },
        },
      },
    };

    return fromPromise(
      (async () => (await this.sesClient.send(new SendEmailCommand(params))).MessageId)(),
      (error) => error as Error,
    );
  }
}
