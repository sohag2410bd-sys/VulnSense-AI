import test from 'node:test';
import assert from 'node:assert/strict';
import {
  executeWithRetryAndFallback,
  isTransientOverloadError,
} from './gemini-retry';

test('isTransientOverloadError recognizes 503 high demand and rate limit errors', () => {
  assert.equal(isTransientOverloadError(new Error('503 Service Unavailable: high demand')), true);
  assert.equal(isTransientOverloadError({ status: 503, message: 'Overloaded' }), true);
  assert.equal(isTransientOverloadError({ status: 429, message: 'RESOURCE_EXHAUSTED' }), true);
  assert.equal(isTransientOverloadError(new Error('API_KEY_INVALID')), false);
  assert.equal(isTransientOverloadError({ status: 403, message: 'PERMISSION_DENIED' }), false);
});

test('executeWithRetryAndFallback retries primary 3 times then switches to fallback model', async () => {
  const calls: string[] = [];
  const sleeps: number[] = [];

  const outcome = await executeWithRetryAndFallback({
    primaryModel: 'gemini-4-hydrogen',
    fallbackModel: 'gemini-3.1-flash-lite',
    maxRetriesPerModel: 3,
    baseDelayMs: 100,
    sleepFn: async (ms) => {
      sleeps.push(ms);
    },
    runModel: async (model) => {
      calls.push(model);
      if (model === 'gemini-4-hydrogen') {
        throw new Error('503 High Demand - model temporarily overloaded');
      }
      return { ok: true, model };
    },
  });

  assert.deepEqual(calls, [
    'gemini-4-hydrogen',
    'gemini-4-hydrogen',
    'gemini-4-hydrogen',
    'gemini-3.1-flash-lite',
  ]);
  assert.deepEqual(sleeps, [100, 200]);
  assert.equal(outcome.modelUsed, 'gemini-3.1-flash-lite');
  assert.equal(outcome.fellBack, true);
  assert.equal(outcome.attempts, 4);
  assert.deepEqual(outcome.result, { ok: true, model: 'gemini-3.1-flash-lite' });
});

test('executeWithRetryAndFallback succeeds on primary retry without falling back', async () => {
  let count = 0;
  const outcome = await executeWithRetryAndFallback({
    primaryModel: 'gemini-4-hydrogen',
    fallbackModel: 'gemini-3.1-flash-lite',
    maxRetriesPerModel: 3,
    baseDelayMs: 50,
    sleepFn: async () => {},
    runModel: async (model) => {
      count += 1;
      if (count < 2) {
        throw { status: 503, message: 'High demand' };
      }
      return `ok-${model}`;
    },
  });

  assert.equal(outcome.modelUsed, 'gemini-4-hydrogen');
  assert.equal(outcome.fellBack, false);
  assert.equal(outcome.attempts, 2);
});

test('executeWithRetryAndFallback fails fast on non-transient 403 errors', async () => {
  let count = 0;
  await assert.rejects(
    () =>
      executeWithRetryAndFallback({
        primaryModel: 'gemini-4-hydrogen',
        fallbackModel: 'gemini-3.1-flash-lite',
        maxRetriesPerModel: 3,
        sleepFn: async () => {},
        runModel: async () => {
          count += 1;
          throw Object.assign(new Error('PERMISSION_DENIED'), { status: 403 });
        },
      }),
    /PERMISSION_DENIED/
  );
  assert.equal(count, 1);
});
