import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import net from 'node:net';

const root = fileURLToPath(new URL('..', import.meta.url));
const frontendPort = Number(process.env.VITE_PORT || 5173);
const children = [];
let stopping = false;

function canConnect(port, host) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port, host });
    const finish = value => { socket.destroy(); resolve(value); };
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.setTimeout(700, () => finish(false));
  });
}

async function isPortInUse(port) {
  // A listener bound to 0.0.0.0 may still allow a loopback bind probe on Windows.
  // Connect to both loopback families instead of probing by trying to bind.
  for (const host of ['127.0.0.1', '::1']) {
    if (await canConnect(port, host)) return true;
  }
  return false;
}

async function existingThreatGuardFrontend(port) {
  for (const host of ['127.0.0.1', '[::1]', 'localhost']) {
    try {
      const response = await fetch(`http://${host}:${port}/`, { signal: AbortSignal.timeout(1200) });
      if (!response.ok) continue;
      const html = await response.text();
      if (html.includes('<title>ThreatGuard — Multi-Source Threat Analyzer</title>') && html.includes('/@vite/client')) return true;
    } catch {
      // Try the next local address; the port check below provides the final diagnosis.
    }
  }
  return false;
}

function start(command, args, options) {
  const child = spawn(command, args, { ...options, stdio: 'inherit' });
  children.push(child);
  child.on('error', error => {
    console.error(`Could not start a ThreatGuard service: ${error.message}`);
    stop(1);
  });
  child.on('exit', code => {
    if (!stopping) {
      console.error(`A ThreatGuard service exited unexpectedly (code ${code ?? 'unknown'}); stopping the other service.`);
      stop(code || 1);
    }
  });
  return child;
}

function terminateTree(child) {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    const killer = spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { stdio: 'ignore', windowsHide: true });
    killer.on('error', () => child.kill());
  } else if (!child.killed) child.kill('SIGTERM');
}

function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  process.exitCode = code;
  for (const child of children) terminateTree(child);
}

async function main() {
  const portInUse = await isPortInUse(frontendPort);
  if (portInUse) {
    if (await existingThreatGuardFrontend(frontendPort)) {
      console.log(`Reusing the ThreatGuard frontend already running on http://localhost:${frontendPort}/.`);
    } else {
      throw new Error(`Port ${frontendPort} is already in use by another service. Stop that process or set VITE_PORT to a free port and update the configured client origin.`);
    }
  } else {
    start(process.execPath, [path.join(root, 'node_modules', 'vite', 'bin', 'vite.js'), '--host', '0.0.0.0', '--strictPort', '--port', String(frontendPort)], { cwd: root });
  }

  // Exit nodemon on an API startup crash so the root runner can stop the
  // frontend it started instead of leaving a misleading Vite-only session.
  start(process.execPath, [path.join(root, 'server', 'node_modules', 'nodemon', 'bin', 'nodemon.js'), '--exitcrash', 'src/index.js'], { cwd: path.join(root, 'server') });
}

process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));
main().catch(error => {
  console.error(`Could not start ThreatGuard: ${error.message}`);
  stop(1);
});
