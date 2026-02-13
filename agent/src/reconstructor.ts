import ObjC from 'frida-objc-bridge';

const O_RDONLY = 0;
const F64 = 64 * 1024;

const MACH_64_HEADER_SIZE = 32;
const MACH_HEADER_SIZE = 28;

const SEEK_SET = 0;
//const SEEK_CUR = 1;
const SEEK_END = 2;

const FAT_MAGIC = 0xCAFEBABE;
const FAT_CIGAM = 0xBEBAFECA;
const MH_MAGIC = 0xFEEDFACE;
const MH_CIGAM = 0xCEFAEDFE;
const MH_MAGIC_64 = 0xFEEDFACF;
const MH_CIGAM_64 = 0xCFFAEDFE;
//const LC_SEGMENT = 0x1;
//const LC_SEGMENT_64 = 0x19;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2C;

const buffer = Memory.alloc(F64);

const open = new NativeFunction(Module.findGlobalExportByName("open") ?? NULL, "int", ["pointer", "int", "int"]);
const read = new NativeFunction(Module.findGlobalExportByName("read") ?? NULL, "int", ["int", "pointer", "int"]);
//const write = new NativeFunction(Module.findGlobalExportByName("write") ?? NULL, "int", ["int", "pointer", "int"]);
const lseek = new NativeFunction(Module.findGlobalExportByName("lseek") ?? NULL, "int64", ["int", "int64", "int"]);
const close = new NativeFunction(Module.findGlobalExportByName("close") ?? NULL, "int", ["int"]);
const strerror_r = new NativeFunction(Module.findGlobalExportByName("strerror_r") ?? NULL, "int", ["int", "pointer", "size_t"]);
const errno = Module.findGlobalExportByName("errno") ?? NULL;

function error(): string {
  const err = errno.readUInt();
  strerror_r(err, buffer, 256);
  return buffer.readUtf8String() ?? '';
}

function swap32(value: number): number {
  const _value = BigInt(value)
  const da_shift = (n: bigint) => ((_value >> n) & 0xFFn) << (24n - n)
  return Number(da_shift(0n) | da_shift(8n) | da_shift(16n) | da_shift(24n))
}

// Send data in chunks of 4K
function sendData(name: string, handle: number, length: number, start: number = 0) {
  let remaining = length;
  while (remaining > 0) {
    const bytesRead = read(handle, buffer, Math.min(F64, remaining))
    if (bytesRead == -1) throw error();
    send({ partial: name, offset: start, size: bytesRead }, buffer.readByteArray(bytesRead));
    remaining -= bytesRead;
    start += bytesRead;
  }
}

function sendMemory(name: string, memory: NativePointer, length: number, start: number = 0) {
  let offset = 0;
  while (offset < length) {
    const bytesRead = Math.min(F64, length - offset)
    send({ partial: name, offset: start, size: bytesRead }, memory.add(offset).readByteArray(bytesRead));
    offset += bytesRead;
    start += bytesRead;
  }
}

function _detectFatMachOffsets(handle: number, moduleAddr: NativePointer): [number, number] {
  // Openfile handle
  const origfileSize = lseek(handle, 0, SEEK_END).toNumber();
  if (origfileSize == -1) throw error();
  lseek(handle, 0, SEEK_SET);

  if (read(handle, buffer, 8) == -1) throw error();

  // Read file magic
  const magic = buffer.readU32();
  let curCpuType = moduleAddr.add(4).readU32();
  let curCpuSubtype = moduleAddr.add(8).readU32();
  // If it's fat
  if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
    var archs = swap32(buffer.add(4).readU32());
    // Each Fat Mach-O entry has 20 bytes
    for (let i = 0; i < archs; i++) {
      if (read(handle, buffer, 20) == -1) throw error();
      var cpuType = swap32(buffer.readU32());
      var cpuSubType = swap32(buffer.add(4).readU32());
      if (curCpuType == cpuType && curCpuSubtype == cpuSubType) {
        return [
          swap32(buffer.add(8).readU32()), // file offset
          swap32(buffer.add(12).readU32()), // file size
        ];
      }
    }
    throw 'Could not find current CPU in FAT Mach-O architectures';
  }
  // If it's not a fat mach-o, just return full file range
  return [0, origfileSize];
}

function _detectEncryptedMachO(modAddr: NativePointer, is64bit: boolean): [number, number, number] | null {
  const ncmds = modAddr.add(16).readU32();
  let off = is64bit ? MACH_64_HEADER_SIZE : MACH_HEADER_SIZE; // starts after mach-o header
  for (let i = 0; i < ncmds; i++) {
    const cmd = modAddr.add(off).readU32();
    const cmdsize = modAddr.add(off + 4).readU32();
    // According to this (https://github.com/subdiox/UnFairPlay/blob/master/unfairplay.c),
    // there should be only one LC_ENCRYPTION header
    // If you encounter an error, please file an issue
    if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
      return [
        off + 16,
        modAddr.add(off + 8).readU32(),
        modAddr.add(off + 12).readU32(),
      ];
    }
    off += cmdsize;
  }
  return null;
}

function _parseAndSendModule(module: Module, relativePath: string): void {
  let is64bit = false;
  const magic = module.base.readU32();

  if (magic == MH_MAGIC || magic == MH_CIGAM) {
    is64bit = false;
  } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
    is64bit = true;
  } else {
    throw `Unknown magic of module ${module.path}`
  }

  // Open file
  const handle = open(Memory.allocUtf8String(module.path), O_RDONLY, 0);
  if (handle == -1) throw error();

  // Detect and extract only current Mach-O
  const [fileStart, fileSize] = _detectFatMachOffsets(handle, module.base);
  send({ start: relativePath, size: fileSize });

  const _encryption = _detectEncryptedMachO(module.base, is64bit);
  lseek(handle, fileStart, SEEK_SET);
  if (_encryption === null) {
    // Not Encrypted, just dump full file (or specific mach-o)
    sendData(relativePath, handle, fileSize);
  }
  else {
    const [offsetCryptId, offsetCrypt, lengthCrypt] = _encryption;
    // Fist, send original data from beginning until CryptId command position
    sendData(relativePath, handle, offsetCryptId);
    // Then, send 4 zeroed bytes to ignore it ...
    buffer.writeU64(0);
    sendMemory(relativePath, buffer, 4, offsetCryptId);
    // ... and adjust file pointer
    lseek(handle, offsetCryptId + 4, SEEK_SET);
    // Now send all file data until encrypted part of binary
    const delta1 = offsetCrypt - (offsetCryptId + 4);
    sendData(relativePath, handle, delta1, offsetCryptId + 4);
    // Now send data loaded from binary
    sendMemory(relativePath, module.base.add(offsetCrypt), lengthCrypt, offsetCrypt);
    // Delta 2 now is first byte passed encrypted part
    const delta2 = offsetCrypt + lengthCrypt;
    // adjust file pointer
    lseek(handle, delta2, SEEK_SET);
    // And send final part
    sendData(relativePath, handle, fileSize - delta2, delta2);
  }
  close(handle);
  send({ end: relativePath })
}

function _sendFile(filePath: string, relativePath: string): void {
  // First, open file and get the size
  const handle = open(Memory.allocUtf8String(filePath), O_RDONLY, 0);
  if (handle == -1) throw error();
  const fileSize = lseek(handle, 0, SEEK_END).toNumber();
  if (fileSize == -1) throw error();
  send({ start: relativePath, size: fileSize });
  lseek(handle, 0, SEEK_SET);
  sendData(relativePath, handle, fileSize);
  close(handle);
  send({ end: relativePath })
}

function correctPath(lastComponent: ObjC.Object, path: ObjC.Object): string {
  const combined = lastComponent.stringByAppend
}

export default function loadAllFiles(appPath: ObjC.Object, moduleMap: Map<string, Module>): void {
  const defaultManager = ObjC.classes.NSFileManager.defaultManager();
  const lastComponent = appPath.lastPathComponent();
  const correctPath = (path: ObjC.Object): string => {
    const combined = lastComponent.stringByAppendingPathComponent_(path);
    return combined.toString();
  }
  send({ directory: lastComponent.toString() });
  const enumerator = defaultManager.enumeratorAtPath_(appPath);
  const isDirPtr = Memory.alloc(Process.pointerSize);
  while (true) {
    const file = enumerator.nextObject()
    if (file === null || file.isNull())
      break;
    const fullPath = appPath.stringByAppendingPathComponent_(file);
    isDirPtr.writePointer(NULL);
    defaultManager.fileExistsAtPath_isDirectory_(fullPath, isDirPtr);
    // If we got a directory
    if (isDirPtr.readU8() == 1) {
      send({ directory: correctPath(file) });
      continue;
    }
    const mod = moduleMap.get(fullPath.toString());
    if (mod !== undefined) {
      _parseAndSendModule(mod, correctPath(file));
      continue;
    }
    if (fullPath.hasSuffix_(".dylib")) {
      const mod = Module.load(fullPath.toString());
      _parseAndSendModule(mod, correctPath(file));
      continue;
    }
    _sendFile(fullPath.toString(), correctPath(file))
  }
}
