import { Result } from 'neverthrow';

// https://github.com/supermacro/neverthrow/issues/179
export type ResultPromise<T, E> = Promise<Result<T, E>>;

export class NotFoundException extends Error {
  constructor(message = 'Not found') {
    super(message);
    this.name = 'NotFoundException';
  }
}
