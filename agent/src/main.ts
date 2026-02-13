import ObjC from 'frida-objc-bridge';
import loadFrameworks from './loader.js';
import loadAllFiles from './reconstructor.js';

Process.findModuleByName('Foundation')?.ensureInitialized();

function getAppModuleMap(appPath: string): Map<string, Module> {
  const modules = Process.enumerateModules().filter(mod => {
    mod.path.includes(appPath);
  });
  const modMap = new Map<string, Module>();
  modules.forEach(m => modMap.set(m.path, m))
  return modMap;
}

function handleMessage(_: any) {
  const appBundle = ObjC.classes.NSBundle.mainBundle();
  const bundlePath = appBundle.bundlePath();
  // First, load frameworks
  loadFrameworks(appBundle);
  // Then, get all app modules
  const appModules = getAppModuleMap(bundlePath.toString());
  // start dump
  loadAllFiles(bundlePath, appModules);
  send({ done: "ok" })
}

recv(handleMessage);
