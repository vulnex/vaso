/**
 * Minimal decoder for Windsurf / Devin Desktop `~/.codeium/windsurf/user_settings.pb`.
 *
 * Since the 3.x generation, Cascade's execution-gate settings live in this
 * protobuf (`exa.codeium_common_pb.UserSettings`), not in the editor's
 * settings.json. Field numbers were taken from the message descriptors in the
 * shipped extension bundle (Devin Desktop 3.10.35). Only the top level is
 * walked; everything else (the ~500 KB server model catalogue in field 52) is
 * skipped by length.
 */

const FIELD_ALLOWED_COMMANDS_PREFIX = 14;
const FIELD_AUTO_EXECUTION_POLICY = 27;
const FIELD_ALLOWED_COMMANDS = 85;
const FIELD_DENIED_COMMANDS = 86;
const FIELD_WEB_AUTO_EXECUTION_POLICY = 90;

/** exa.codeium_common_pb.CascadeCommandsAutoExecution; EAGER is the UI's "Turbo". */
const COMMAND_POLICIES: Record<number, string> = { 1: 'off', 2: 'auto', 3: 'turbo', 4: 'disabled' };
/** exa.codeium_common_pb.CascadeWebRequestsAutoExecution */
const WEB_POLICIES: Record<number, string> = { 1: 'disabled', 2: 'allowlist', 3: 'turbo' };

export interface WindsurfUserSettings {
  autoExecutionPolicy?: string;
  webRequestsAutoExecutionPolicy?: string;
  allowedCommands: string[];
  deniedCommands: string[];
}

function readVarint(buf: Uint8Array, pos: number): [number, number] {
  let result = 0;
  let shift = 0;
  for (;;) {
    if (pos >= buf.length) throw new Error('truncated varint');
    const byte = buf[pos++];
    // Enum/length values here fit well within 2^31; avoid bitwise overflow anyway
    result += (byte & 0x7f) * 2 ** shift;
    if (byte < 0x80) return [result, pos];
    shift += 7;
    if (shift > 63) throw new Error('varint too long');
  }
}

/** Returns undefined when the bytes aren't a well-formed protobuf message. */
export function decodeWindsurfUserSettings(buf: Uint8Array): WindsurfUserSettings | undefined {
  const settings: WindsurfUserSettings = { allowedCommands: [], deniedCommands: [] };
  const decoder = new TextDecoder();
  let pos = 0;
  try {
    while (pos < buf.length) {
      let key: number;
      [key, pos] = readVarint(buf, pos);
      const field = Math.floor(key / 8);
      const wireType = key % 8;
      if (field === 0) return undefined;

      if (wireType === 0) {
        let value: number;
        [value, pos] = readVarint(buf, pos);
        if (field === FIELD_AUTO_EXECUTION_POLICY) {
          settings.autoExecutionPolicy = COMMAND_POLICIES[value] ?? `unknown(${value})`;
        } else if (field === FIELD_WEB_AUTO_EXECUTION_POLICY) {
          settings.webRequestsAutoExecutionPolicy = WEB_POLICIES[value] ?? `unknown(${value})`;
        }
      } else if (wireType === 2) {
        let len: number;
        [len, pos] = readVarint(buf, pos);
        if (pos + len > buf.length) return undefined;
        if (field === FIELD_ALLOWED_COMMANDS || field === FIELD_ALLOWED_COMMANDS_PREFIX) {
          settings.allowedCommands.push(decoder.decode(buf.subarray(pos, pos + len)));
        } else if (field === FIELD_DENIED_COMMANDS) {
          settings.deniedCommands.push(decoder.decode(buf.subarray(pos, pos + len)));
        }
        pos += len;
      } else if (wireType === 1) {
        pos += 8;
      } else if (wireType === 5) {
        pos += 4;
      } else {
        return undefined;
      }
    }
  } catch {
    return undefined;
  }
  return pos === buf.length ? settings : undefined;
}

/**
 * Project the decoded settings onto the `windsurf.*` key vocabulary the
 * WS-001/WS-002 checks already read from settings.json.
 */
export function toWindsurfSettingsData(s: WindsurfUserSettings): Record<string, unknown> {
  const windsurf: Record<string, unknown> = {};
  if (s.autoExecutionPolicy) windsurf.autoExecutionPolicy = s.autoExecutionPolicy;
  if (s.webRequestsAutoExecutionPolicy) windsurf.webRequestsAutoExecutionPolicy = s.webRequestsAutoExecutionPolicy;
  if (s.allowedCommands.length > 0) windsurf.cascadeCommandsAllowList = s.allowedCommands;
  if (s.deniedCommands.length > 0) windsurf.cascadeCommandsDenyList = s.deniedCommands;
  return { windsurf };
}
