import ObjC from 'frida-objc-bridge';

export default function throwIfError<T>(cb: (error: NativePointer) => T): T {
  var errorPtr = Memory.alloc(Process.pointerSize);
  errorPtr.writePointer(NULL);
  const res = cb(errorPtr);
  if (!errorPtr.readPointer().isNull()) {
    const err = new ObjC.Object(errorPtr.readPointer());
    throw `Error: ${err.code()}`//err.localizedDescription().toString();
  }
  return res;
}
