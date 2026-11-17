export interface RetryFallbackOptions<T> {
  primaryModel: string;
  fallbackModel: string;
  maxRetriesPerModel?: number;
  baseDelayMs?: number;
  runModel: (model: string) => Promise<T>;
  sleepFn?: (ms: number) => Promise<void>;
}

export interface RetryFallbackResult<T> {
  result: T;
  modelUsed: string;
  attempts: number;
  fellBack: boolean;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function isTransientOverloadError(error: unknown): boolean {
  if (!error) return false;

  const maybeObj = error as { status?: number; code?: number | string; message?: string };
  const status = Number(maybeObj.status ?? maybeObj.code);
  if (status === 503 || status === 429 || status === 502 || status === 504) {
    return true;
  }

  const message =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
      ? error
      : JSON.stringify(error);

  const lower = message.toLowerCase();
  return (
    lower.includes('503') ||
    lower.includes('429') ||
    lower.includes('high demand') ||
    lower.includes('overloaded') ||
    lower.includes('unavailable') ||
    lower.includes('resource_exhausted') ||
    lower.includes('rate limit') ||
    lower.includes('temporarily') ||
    lower.includes('timeout') ||
    lower.includes('econnreset')
  );
}

export async function executeWithRetryAndFallback<T>({
  primaryModel,
  fallbackModel,
  maxRetriesPerModel = 3,
  baseDelayMs = 1200,
  runModel,
  sleepFn = defaultSleep,
}: RetryFallbackOptions<T>): Promise<RetryFallbackResult<T>> {
  let totalAttempts = 0;
  let lastError: unknown;

  const modelsToTry =
    fallbackModel && fallbackModel !== primaryModel
      ? [primaryModel, fallbackModel]
      : [primaryModel];

  for (let modelIdx = 0; modelIdx < modelsToTry.length; modelIdx++) {
    const model = modelsToTry[modelIdx];
    const isFallback = modelIdx > 0;

    for (let attempt = 1; attempt <= maxRetriesPerModel; attempt++) {
      totalAttempts += 1;
      try {
        const result = await runModel(model);
        return {
          result,
          modelUsed: model,
          attempts: totalAttempts,
          fellBack: isFallback,
        };
      } catch (err) {
        lastError = err;
        const transient = isTransientOverloadError(err);

        if (!transient) {
          throw err;
        }

        if (attempt < maxRetriesPerModel) {
          const delayMs = baseDelayMs * Math.pow(2, attempt - 1);
          await sleepFn(delayMs);
        }
      }
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error('All Gemini model attempts failed due to temporary service overload.');
}
