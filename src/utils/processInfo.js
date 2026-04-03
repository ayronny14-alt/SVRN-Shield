import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { platform } from 'node:os';

const exec = promisify(execFile);
const PLATFORM = platform();

/**
 * Resolve a PID to its command line and parent process info.
 * @param {number} pid
 * @returns {Promise<object|null>}
 */
export async function getProcessInfo(pid) {
  if (!pid || pid <= 0) return null;

  try {
    if (PLATFORM === 'win32') {
      // Windows: use Get-CimInstance (modern) or Get-Process
      const cmd = `Get-CimInstance Win32_Process -Filter "ProcessId = ${pid}" | Select-Object ProcessId,ParentProcessId,CommandLine,ExecutablePath | ConvertTo-Json`;
      const { stdout } = await exec('powershell', ['-Command', cmd], { timeout: 3000 });
      if (!stdout.trim()) return null;
      const data = JSON.parse(stdout);
      return {
        pid: data.ProcessId,
        ppid: data.ParentProcessId,
        commandLine: data.CommandLine,
        path: data.ExecutablePath,
        name: data.CommandLine?.split(' ')[0].split('\\').pop() || 'unknown',
      };
    } else {
      // Linux/macOS: use ps
      const { stdout } = await exec('ps', ['-p', pid, '-o', 'ppid,args', '--no-headers'], { timeout: 2000 });
      if (!stdout.trim()) return null;
      const parts = stdout.trim().split(/\s+/);
      const ppid = parseInt(parts[0], 10);
      const commandLine = parts.slice(1).join(' ');
      return {
        pid,
        ppid,
        commandLine,
        name: commandLine.split(' ')[0].split('/').pop(),
      };
    }
  } catch {
    return null;
  }
}

/**
 * Cache for process info to avoid slamming the OS with exec calls.
 */
class ProcessCache {
  constructor(ttl = 30_000) {
    this._cache = new Map();
    this._ttl = ttl;
  }

  async get(pid) {
    const entry = this._cache.get(pid);
    if (entry && Date.now() - entry.ts < this._ttl) return entry.data;

    const data = await getProcessInfo(pid);
    if (data) {
      this._cache.set(pid, { ts: Date.now(), data });
    }
    return data;
  }

  clear() { this._cache.clear(); }
}

export const processCache = new ProcessCache();
