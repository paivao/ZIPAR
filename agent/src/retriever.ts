import ObjC from 'frida-objc-bridge';

const O_RDONLY = 0;
const KKKK = 4 * 1024;

const SEEK_SET = 0;
const SEEK_CUR = 1;
const SEEK_END = 2;

const FAT_MAGIC = 0xCAFEBABE;
const FAT_CIGAM = 0xBEBAFECA;
const MH_MAGIC = 0xFEEDFACE;
const MH_CIGAM = 0xCEFAEDFE;
const MH_MAGIC_64 = 0xFEEDFACF;
const MH_CIGAM_64 = 0xCFFAEDFE;
const LC_SEGMENT = 0x1;
const LC_SEGMENT_64 = 0x19;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2C;

const open = new NativeFunction(Module.findGlobalExportByName("open") ?? NULL, "int", ["pointer", "int", "int"]);
const read = new NativeFunction(Module.findGlobalExportByName("read") ?? NULL, "int", ["int", "pointer", "int"]);
const write = new NativeFunction(Module.findGlobalExportByName("write") ?? NULL, "int", ["int", "pointer", "int"]);
const lseek = new NativeFunction(Module.findGlobalExportByName("lseek") ?? NULL, "int64", ["int", "int64", "int"]);
const close = new NativeFunction(Module.findGlobalExportByName("close") ?? NULL, "int", ["int"]);
const strerror_r = new NativeFunction(Module.findGlobalExportByName("strerror_r") ?? NULL, "int", ["int", "pointer", "size_t"]);
const errno = Module.findGlobalExportByName("errno") ?? NULL;

function error(): string {
  const err = errno.readUInt();
  const buffer = Memory.alloc(256);
  strerror_r(err, buffer, 256);
  return buffer.readUtf8String() ?? '';
}

function swap32(value: number): number {
  const _value = BigInt(value)
  const da_shift = (n: bigint) => ((_value >> n) & 0xFFn) << (24n - n)
  return Number(da_shift(0n) | da_shift(8n) | da_shift(16n) | da_shift(24n))
}

function _parseAndSendModule(module: Module, relativePath: string): void {
  let is64bit = false;
  let sizeOfMachHeader = 0;
  let magic = module.base.readU32();
  let cur_cpu_type = module.base.add(4).readU32();
  let cur_cpu_subtype = module.base.add(8).readU32();
  if (magic == MH_MAGIC || magic == MH_CIGAM) {
    is64bit = false;
    sizeOfMachHeader = 28;
  } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
    is64bit = true;
    sizeOfMachHeader = 32;
  } else {
    throw `Unknown magic of module ${module.path}`
  }

}

function _sendFile(filePath: string, relativePath: string): void {
  // First, open file and get the size
  const handle = open(Memory.allocUtf8String(filePath), O_RDONLY, 0);
  if (handle == -1) throw error();
  const fileSize = lseek(handle, 0, SEEK_END).toNumber();
  if (fileSize == -1) throw error();
  send({ start: relativePath, size: fileSize })
  // Now, make an big buffer and send chunks
  const buffer = Memory.alloc(KKKK);
  let offset = 0;
  lseek(handle, 0, SEEK_SET);
  while (offset < fileSize) {
    const bytesRead = read(handle, buffer, KKKK)
    if (bytesRead == -1) throw error();
    send({ partial: relativePath, offset: offset, size: bytesRead }, buffer.readByteArray(bytesRead));
    offset += bytesRead
  }
  close(handle);
  send({ end: relativePath })
}

export default function loadAllFiles(appPath: ObjC.Object, moduleMap: Map<string, Module>): void {
  const defaultManager = ObjC.classes.NSFileManager.defaultManager();
  const enumerator = defaultManager.enumeratorAtPath_(appPath);
  const isDirPtr = Memory.alloc(Process.pointerSize);
  while (true) {
    const file = enumerator.nextObject()
    if (file.isNull())
      break;
    const fullPath = appPath.stringByAppendingPathComponent_(file);
    isDirPtr.writePointer(NULL);
    defaultManager.fileExistsAtPath_isDirectory_(fullPath, isDirPtr);
    // If we got a directory
    if (isDirPtr.readULong() === 1) {
      send({ directory: fullPath.toString() });
      continue;
    }
    const mod = moduleMap.get(fullPath.toString())
    if (mod !== undefined) {
      _parseAndSendModule(mod, file.toString());
      continue;
    }
    if (fullPath.hasSuffix_(".dylib")) {
      const mod = Module.load(fullPath.toString());
      _parseAndSendModule(mod, file.toString());
      continue;
    }
    _sendFile(fullPath.toString(), file.toString())
  }
}
