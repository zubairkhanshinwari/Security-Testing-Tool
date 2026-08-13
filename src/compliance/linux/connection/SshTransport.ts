import type { CommandExecutionResult } from './LinuxConnectionProvider';

export interface SshConnectOptions {
  host: string;
  port: number;
  username: string;
  privateKey: string;
  passphrase?: string;
  readyTimeoutMs: number;
}

/**
 * Minimal transport seam between SshLinuxConnectionProvider and an actual SSH
 * client library. Production code resolves a NodeSshTransport (backed by the
 * `ssh2` package) lazily; tests inject a fake implementing this same
 * interface, so the unit suite never needs a real network connection or the
 * `ssh2` package installed.
 */
export interface SshTransport {
  connect(options: SshConnectOptions): Promise<void>;
  exec(program: string, args: string[], timeoutMs: number): Promise<CommandExecutionResult>;
  end(): Promise<void>;
}

/**
 * Lazily requires the `ssh2` package so importing this module (and the rest
 * of the compliance pipeline) never fails in environments/tests where the
 * optional dependency isn't installed.
 */
export class NodeSshTransport implements SshTransport {
  // Typed as `any`: the `ssh2` package (and its type definitions) is an
  // optional runtime dependency, lazily require()'d only when an actual SSH
  // connection is attempted, so this module — and every unit test that
  // depends on it transitively — never needs `ssh2` installed to type-check.
  private client: any;

  async connect(options: SshConnectOptions): Promise<void> {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { Client } = require('ssh2');
    const client = new Client();
    this.client = client;

    await new Promise<void>((resolve, reject) => {
      client
        .on('ready', () => resolve())
        .on('error', (err: Error) => reject(err))
        .connect({
          host: options.host,
          port: options.port,
          username: options.username,
          privateKey: options.privateKey,
          passphrase: options.passphrase,
          readyTimeout: options.readyTimeoutMs,
        });
    });
  }

  async exec(program: string, args: string[], timeoutMs: number): Promise<CommandExecutionResult> {
    if (!this.client) throw new Error('SSH transport is not connected.');
    const client = this.client;
    const command = buildSafeCommandLine(program, args);

    return new Promise<CommandExecutionResult>((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        reject(new Error(`SSH command timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      client.exec(command, (err: Error | undefined, stream: any) => {
        if (err) {
          clearTimeout(timer);
          return reject(err);
        }
        stream
          .on('close', (code: number | null) => {
            clearTimeout(timer);
            resolve({ stdout, stderr, exitCode: code });
          })
          .on('data', (data: Buffer) => {
            stdout += data.toString('utf8');
          })
          .stderr.on('data', (data: Buffer) => {
            stderr += data.toString('utf8');
          });
      });
    });
  }

  async end(): Promise<void> {
    this.client?.end();
    this.client = undefined;
  }
}

/**
 * Builds a single-quoted, non-interpolated command line for ssh2's exec().
 * Every argument is single-quote-escaped so shell metacharacters in a target
 * (already validated by commandAllowlist's strict regexes) can never be
 * reinterpreted by the remote shell.
 */
function buildSafeCommandLine(program: string, args: string[]): string {
  const quote = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`;
  return [quote(program), ...args.map(quote)].join(' ');
}
