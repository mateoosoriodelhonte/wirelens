import { Ajv2020 } from 'ajv/dist/2020.js';
import type { ErrorObject, ValidateFunction } from 'ajv';
import captureSchema from '../capture.schema.json' with { type: 'json' };
import type { CaptureDocument } from './capture.js';

export class ContractValidationError extends Error {
  readonly errors: ErrorObject[];

  constructor(message: string, errors: ErrorObject[] = []) {
    super(message);
    this.name = 'ContractValidationError';
    this.errors = errors;
  }
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate: ValidateFunction<CaptureDocument> = ajv.compile<CaptureDocument>(captureSchema);

export function validateCaptureDocument(value: unknown): CaptureDocument {
  if (!validate(value)) {
    const errors = validate.errors ?? [];
    const versionError = errors.find((error) => error.instancePath === '/contractVersion');
    const message = versionError
      ? 'Invalid contractVersion: expected WireLens contract version 1.0.0'
      : `Invalid capture document: ${ajv.errorsText(errors)}`;
    throw new ContractValidationError(message, errors);
  }
  return value;
}
