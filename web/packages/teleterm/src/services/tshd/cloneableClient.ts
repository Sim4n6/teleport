/**
 * Teleport
 * Copyright (C) 2024 Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import {
  RpcInputStream,
  UnaryCall,
  ClientStreamingCall,
  ServerStreamingCall,
  DuplexStreamingCall,
  RpcOutputStream,
  RpcError,
  RpcOptions,
  ServiceInfo,
  FinishedUnaryCall,
} from '@protobuf-ts/runtime-rpc';

/**
 * Transforms a class-based client to an object that can be passed
 * over the context bridge.
 * Errors returned from its methods are converted to `TshdRpcError` objects.
 *
 * Why is such transformation needed?
 * In Electron, preload and renderer contexts are isolated with a context bridge.
 * The preload runs the tshd client, and the renderer runs the React app.
 * That means that whatever the tshd client returns has to pass through that bridge.
 *
 * In this particular scenario, this causes all custom properties on `Error` to be lost.
 * To remedy this, we convert them to custom `TshdRpcError`
 * objects for each call type.
 * Additionally, the client itself needs to be converted to an object
 * (the client generated by `protobuf-ts` is class-based).
 * Class methods are lost after crossing the bridge.
 *
 * Read more https://www.electronjs.org/docs/latest/api/context-bridge.
 */
export function cloneClient<Client extends ServiceInfo>(
  classClient: Client
): CloneableClient<Client> {
  return classClient.methods.reduce<CloneableClient<Client>>(
    (objectClient, method) => {
      const methodName = method.localName;
      // To avoid a problem with `this`
      // being lost, we use wrap it into an arrow function.
      const classMethod = (...args) => classClient[methodName](...args);
      // unary
      if (!method.clientStreaming && !method.serverStreaming) {
        objectClient[methodName] = cloneUnaryCall(classMethod);
      }
      // client streaming
      if (method.clientStreaming && !method.serverStreaming) {
        objectClient[methodName] = cloneClientStreamingCall(classMethod);
      }
      // server streaming
      if (!method.clientStreaming && method.serverStreaming) {
        objectClient[methodName] = cloneServerStreamingCall(classMethod);
      }
      // duplex
      if (method.clientStreaming && method.serverStreaming) {
        objectClient[methodName] = cloneDuplexStreamingCall(classMethod);
      }
      return objectClient;
    },
    {} as CloneableClient<Client>
  );
}

/**
 * Converts a regular `AbortSignal` to the signal
 * that can be passed over the context bridge.
 */
export function cloneAbortSignal(signal: AbortSignal): CloneableAbortSignal {
  const cloned: Writeable<CloneableAbortSignal> = {
    canBePassedThroughContextBridge: true,
    onabort: (...args) => signal.onabort(...args),
    throwIfAborted: () => signal.throwIfAborted(),
    reason: signal.reason,
    aborted: signal.aborted,
    dispatchEvent: (...args) => signal.dispatchEvent(...args),
    addEventListener: (type, listener, options) =>
      signal.addEventListener(type, listener, options),
    removeEventListener: (type, listener, options) =>
      signal.removeEventListener(type, listener, options),
    eventListeners: (...args) => signal.eventListeners(...args),
    removeAllListeners: (...args) => signal.removeAllListeners(...args),
  };

  signal.addEventListener(
    'abort',
    () => {
      cloned.reason = signal.reason;
      cloned.aborted = signal.aborted;
    },
    {
      // Catch the abort event before other listeners to update properties.
      capture: true,
      once: true,
    }
  );

  return cloned;
}

/**
 * An abort signal that can be passed over the context bridge.
 * Can be produced with `cloneAbortSignal()`.
 */
export type CloneableAbortSignal = AbortSignal & {
  /**
   * It's an arbitrary property that lets us distinguish `CloneableAbortSignal`
   * from `AbortSignal` on type level.
   */
  canBePassedThroughContextBridge: true;
};

type Writeable<T> = {
  -readonly [P in keyof T]: T[P];
};

/**
 * User-provided options for Remote Procedure Calls.
 *
 * The only difference from the original `RpcOptions` is the abort signal.
 * The regular one is replaced with `CloneableAbortSignal`
 * that can be passed over the context bridge.
 */
export type CloneableRpcOptions = Omit<RpcOptions, 'abort'> & {
  abort?: CloneableAbortSignal;
};

/**
 * Describes a client that can be passed over the context bridge.
 * Errors returned from its methods are converted to `TshdRpcError` objects.
 */
export type CloneableClient<Client> = {
  [Method in keyof Client]: Client[Method] extends (
    ...args: infer Args
  ) => infer ReturnType
    ? (
        ...args: { [K in keyof Args]: ReplaceRpcOptions<Args[K]> }
      ) => CloneableCallTypes<ReturnType>
    : never;
};

type CloneableCallTypes<T> =
  T extends UnaryCall<infer Req, infer Res>
    ? CloneableUnaryCall<Req, Res>
    : T extends ClientStreamingCall<infer Req, infer Res>
      ? CloneableClientStreamingCall<Req, Res>
      : T extends ServerStreamingCall<infer Req, infer Res>
        ? CloneableServerStreamingCall<Req, Res>
        : T extends DuplexStreamingCall<infer Req, infer Res>
          ? CloneableDuplexStreamingCall<Req, Res>
          : never;

type ReplaceRpcOptions<T> = T extends RpcOptions ? CloneableRpcOptions : T;

type CloneableUnaryCall<I extends object, O extends object> = Pick<
  UnaryCall<I, O>,
  'then'
>;

type CloneableClientStreamingCall<I extends object, O extends object> = Pick<
  ClientStreamingCall<I, O>,
  'requests' | 'then'
>;

type CloneableServerStreamingCall<I extends object, O extends object> = Pick<
  ServerStreamingCall<I, O>,
  'responses' | 'then'
>;

type CloneableDuplexStreamingCall<I extends object, O extends object> = Pick<
  DuplexStreamingCall<I, O>,
  'requests' | 'responses' | 'then'
>;

function cloneUnaryCall<I extends object, O extends object>(
  call: (input: I, options?: CloneableRpcOptions) => UnaryCall<I, O>
): (input: I, options?: CloneableRpcOptions) => CloneableUnaryCall<I, O> {
  return (input, options) => {
    const output = call(input, options);
    return { then: cloneThenRejection(output.then.bind(output)) };
  };
}

function cloneClientStreamingCall<I extends object, O extends object>(
  call: (options?: CloneableRpcOptions) => ClientStreamingCall<I, O>
): (options?: CloneableRpcOptions) => CloneableClientStreamingCall<I, O> {
  return options => {
    const output = call(options);
    return {
      requests: cloneRequests(output.requests),
      then: cloneThenRejection(output.then.bind(output)),
    };
  };
}

function cloneServerStreamingCall<I extends object, O extends object>(
  call: (input: I, options?: CloneableRpcOptions) => ServerStreamingCall<I, O>
): (
  input: I,
  options?: CloneableRpcOptions
) => CloneableServerStreamingCall<I, O> {
  return (input, options) => {
    const output = call(input, options);
    return {
      responses: cloneResponses(output.responses),
      then: cloneThenRejection(output.then.bind(output)),
    };
  };
}

function cloneDuplexStreamingCall<I extends object, O extends object>(
  call: (options?: CloneableRpcOptions) => DuplexStreamingCall<I, O>
): (options?: CloneableRpcOptions) => CloneableDuplexStreamingCall<I, O> {
  return options => {
    const output = call(options);
    return {
      requests: cloneRequests(output.requests),
      responses: cloneResponses(output.responses),
      then: cloneThenRejection(output.then.bind(output)),
    };
  };
}

/**
 * An object that is thrown when an RPC fails.
 * Preserves properties that would normally be lost after `Error` has passed
 * through the context bridge.
 */
export type TshdRpcError = Pick<
  RpcError,
  'message' | 'stack' | 'cause' | 'code'
> & {
  name: 'TshdRpcError';
  /**
   * `true` if the error can be resolved by logging in again.
   * It is taken from the error metadata.
   */
  isResolvableWithRelogin: boolean;
};

/** Checks if the given value is a `TshdRpcError`. */
export function isTshdRpcError(error: unknown): error is TshdRpcError {
  return error['name'] === 'TshdRpcError';
}

function cloneError(error: unknown): TshdRpcError | Error | unknown {
  if (error instanceof RpcError) {
    return {
      name: 'TshdRpcError',
      message: error.message,
      stack: error.stack,
      cause: error.cause,
      code: error.code,
      isResolvableWithRelogin: error.meta['is-resolvable-with-relogin'] === '1',
    } satisfies TshdRpcError;
  }

  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
      cause: error.cause,
    } satisfies Error;
  }

  return error;
}

function cloneRequests<O extends object>(
  original: RpcInputStream<O>
): RpcInputStream<O> {
  return {
    send: (...args) => original.send(...args),
    complete: (...args) => original.complete(...args),
  };
}

function cloneResponses<O extends object>(
  original: RpcOutputStream<O>
): RpcOutputStream<O> {
  return {
    [Symbol.asyncIterator]: original[Symbol.asyncIterator],
    onMessage: (...args) => original.onMessage(...args),
    onComplete: (...args) => original.onComplete(...args),
    onError: errorCallback =>
      original.onError(e => errorCallback(cloneError(e) as Error)),
    onNext: callback =>
      original.onNext((message, error, complete) =>
        callback(message, cloneError(error) as Error, complete)
      ),
  };
}

async function clonePromiseRejection<TResult>(
  promise: Promise<TResult>
): Promise<TResult> {
  try {
    return await promise;
  } catch (e) {
    throw cloneError(e);
  }
}

function cloneThenRejection<TResult>(
  then: Promise<TResult>['then']
): Promise<TResult>['then'] {
  return (onFulfilled, onRejected) => {
    // If onRejected callback is provided, then it will handle the rejection.
    if (onRejected) {
      return then(onFulfilled, reason => onRejected(cloneError(reason)));
    }
    return clonePromiseRejection(then(onFulfilled));
  };
}

/*
 * Mocks for tests.
 */

/**
 * A helper for mocking unary calls. Creates a promise-like instance of a class which resolves to
 * an object where only the response field contains something. If error is passed, the instance
 * rejects with that error.
 *
 * The need for this helper stems from the fact that cloneableClient returns the whole then property
 * of a unary call, so TypeScript expects the types to match.
 *
 * Alternatively, we could change cloneableClient to merely return the response property, plus maybe
 * some other fields that we need.
 */
export class MockedUnaryCall<Response extends object>
  implements CloneableUnaryCall<any, Response>
{
  constructor(
    public response: Response,
    private error?: any
  ) {}

  // The signature of then was autocompleted by TypeScript language server.
  then<TResult1 = FinishedUnaryCall<any, Response>, TResult2 = never>(
    onfulfilled?: (
      value: FinishedUnaryCall<any, Response>
    ) => TResult1 | PromiseLike<TResult1>,
    onrejected?: (reason: any) => TResult2 | PromiseLike<TResult2>
  ): Promise<TResult1 | TResult2> {
    if (this.error) {
      return Promise.reject(onrejected(this.error));
    }

    return Promise.resolve(
      onfulfilled({
        response: this.response,
        method: undefined,
        requestHeaders: undefined,
        request: undefined,
        headers: undefined,
        status: undefined,
        trailers: undefined,
      })
    );
  }
}
