import {
  createServiceTokenProvider,
  isServiceTokenError,
  type ServiceTokenProvider,
  type ServiceTokenProviderOptions,
} from "@hivemagnus/hive-common/oathweave";

/**
 * Oathweave client-credentials tokens for the collector, from hive-common's
 * `createServiceTokenProvider()`: fetched on first use, cached, replaced
 * before they expire, one request shared between concurrent callers, and a
 * short backoff after a failure. Token URLs must be HTTPS.
 *
 * Failures keep the collector's own messages (they reach source health and
 * the log): `httpMessage(status)` for an error status from the token
 * endpoint, otherwise hive-common's fixed message. Neither ever holds the
 * client secret, a token or the endpoint's response body.
 */
export function collectorTokenProvider(
  options: ServiceTokenProviderOptions,
  httpMessage: (status: number) => string,
): ServiceTokenProvider {
  const provider = createServiceTokenProvider(options);
  return {
    token: () =>
      provider.token().catch((error: unknown) => {
        if (!isServiceTokenError(error)) throw error;
        throw new Error(
          error.reason === "http" && error.upstreamStatus !== undefined
            ? httpMessage(error.upstreamStatus)
            : error.message,
        );
      }),
    invalidate: () => provider.invalidate(),
  };
}

export type { ServiceTokenProvider };
