import ObjC from 'frida-objc-bridge';

import throwIfError from './error.js';

function _loadFramework(frameworkPath: ObjC.Object): void {
  const defaultManager = ObjC.classes.NSFileManager.defaultManager();
  if (!defaultManager.fileExistsAtPath_(frameworkPath)) {
    console.info(`Framework bundle path doesn't exist: ${frameworkPath.toString()}`)
    return;
  }
  const frameworkDirs = throwIfError<ObjC.Object>(e => defaultManager.contentsOfDirectoryAtPath_error_(frameworkPath, e));
  const count = frameworkDirs.count();
  for (let i = 0; i < count; i++) {
    const frameworkDir = frameworkDirs.objectAtIndex_(i);
    const fullPath = frameworkPath.stringByAppendingPathComponent_(frameworkDir);
    const bundle = ObjC.classes.NSBundle.bundleWithPath_(fullPath);
    if (bundle === null || bundle.isNull()) {
      console.warn(`Framework directory is not bundle: ${frameworkDir.toString()}`)
      continue;
    }
    const loaded = bundle.load() as boolean;
    if (!loaded)
      console.warn(`Could not load framework: ${frameworkDir.toString()}`)
  }
}

export default function loadFrameworks(appBundle: ObjC.Object): void {
  if (appBundle.$className != "NSBundle") {
    throw `AppBundle is not an NSBundle class. It is ${appBundle.$className}`
  }
  _loadFramework(appBundle.privateFrameworksPath())
  _loadFramework(appBundle.sharedFrameworksPath())
}
