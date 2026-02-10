import ObjC from 'frida-objc-bridge';

Process.findModuleByName('Foundation')?.ensureInitialized();

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

const wrapped: {[key: string]: NativeFunction<NativeFunctionReturnValue,NativeFunctionArgumentValue[]>} = {};
const wrapped_signatures: {[key: string]: [NativeFunctionReturnType, NativeFunctionArgumentType[]]} = {
  "NSSearchPathForDirectoriesInDomains": ["pointer", ["int", "int", "int"]],
  "open": ["int", ["pointer", "int", "int"]],
  "read": ["int", ["int", "pointer", "int"]],
  "write": ["int", ["int", "pointer", "int"]],
  "lseek": ["int64", ["int", "int64", "int"]],
  "close": ["int", ["int"]],
  "remove": ["int", ["pointer"]],
  "access": ["int", ["pointer", "int"]],
  "dlopen": ["pointer", ["pointer", "int"]],
};
for (const [name, [ret, args]] of Object.entries(wrapped_signatures)) {
  const nptr = Module.findGlobalExportByName(name);
  if (nptr === null) {
    continue;
  }
  wrapped[name] = new NativeFunction(nptr, ret, args);
}

const allocStr = Memory.allocUtf8String;

function getDocumentDir() {
    var NSDocumentDirectory = 9;
    var NSUserDomainMask = 1;
    var npdirs = wrapped.NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1) as NativePointer;
    return (new ObjC.Object(npdirs)).objectAtIndex_(0).toString();
}

function open(pathname: string | NativePointer, flags: number, mode: number):number {
    if (typeof pathname === "string") {
        pathname = allocStr(pathname);
    }
    return wrapped.open(pathname, flags, mode) as number;
}

function getAllAppModules() {
  const modules: Module[] = [];
    const tmpmods = Process.enumerateModules();
    for (let i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}
const modules = getAllAppModules();

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str: string, n:number) {
  return "0".repeat(n-str.length) + str;
}

function swap32(value:number): number {
    const strvalue = pad(value.toString(16),8)
    var result = "";
    for(let i = 0; i < strvalue.length; i=i+2){
        result += strvalue.charAt(strvalue.length - i - 2);
        result += strvalue.charAt(strvalue.length - i - 1);
    }
    return parseInt(result,16)
}

function dumpModule(name: string) {
    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        console.log("Cannot find module");
        return;
    }
    var modbase = modules[i].base;
    var modsize = modules[i].size;
    var newmodname = modules[i].name;
    var newmodpath = getDocumentDir() + "/" + newmodname + ".fid";
    var oldmodpath = modules[i].path;


    if(!wrapped.access(allocStr(newmodpath),0)){
        wrapped.remove(allocStr(newmodpath));
    }

    var fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
    var foldmodule = open(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 || foldmodule == -1) {
        console.log("Cannot open file" + newmodpath);
        return;
    }

    var is64bit = false;
    var size_of_mach_header = 0;
    var magic = modbase.readU32();
    var cur_cpu_type = modbase.add(4).readU32();
    var cur_cpu_subtype = modbase.add(8).readU32();
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    }else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    }

    var BUFSIZE = 4096;
    var buffer = Memory.alloc(BUFSIZE);

    wrapped.read(foldmodule, buffer, BUFSIZE);

    var fileoffset = 0;
    var filesize = 0;
    magic = buffer.readU32();
    if(magic == FAT_CIGAM || magic == FAT_MAGIC){
        var off = 4;
        var archs = swap32(buffer.add(off).readU32());
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(buffer.add(off + 4).readU32());
            var cpusubtype = swap32(buffer.add(off + 8).readU32());
            if(cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype){
                fileoffset = swap32(buffer.add(off + 12).readU32());
                filesize = swap32(buffer.add(off + 16).readU32());
                break;
            }
            off += 20;
        }

        if(fileoffset == 0 || filesize == 0)
            return;

        wrapped.lseek(fmodule, 0, SEEK_SET);
        wrapped.lseek(foldmodule, fileoffset, SEEK_SET);
        const fileInBufCount = Math.floor(filesize / BUFSIZE);
        for(var i = 0; i < fileInBufCount; i++) {
            wrapped.read(foldmodule, buffer, BUFSIZE);
            wrapped.write(fmodule, buffer, BUFSIZE);
        }
        if(filesize % BUFSIZE){
            wrapped.read(foldmodule, buffer, filesize % BUFSIZE);
            wrapped.write(fmodule, buffer, filesize % BUFSIZE);
        }
    }else{
        var readLen = 0;
        wrapped.lseek(foldmodule, 0, SEEK_SET);
        wrapped.lseek(fmodule, 0, SEEK_SET);
        while(readLen = wrapped.read(foldmodule, buffer, BUFSIZE) as number) {
            wrapped.write(fmodule, buffer, readLen);
        }
    }

    var ncmds = modbase.add(16).readU32();
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    var segments = [];
    for (var i = 0; i < ncmds; i++) {
        var cmd = modbase.add(off).readU32();
        var cmdsize = modbase.add(off + 4).readU32();
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = modbase.add(off + 8).readU32();
            crypt_size = modbase.add(off + 12).readU32();
        }
        off += cmdsize;
    }

    if (offset_cryptid != -1) {
        var tpbuf = Memory.alloc(8);
        tpbuf.writeU64(0);
        wrapped.lseek(fmodule, offset_cryptid, SEEK_SET);
        wrapped.write(fmodule, tpbuf, 4);
        wrapped.lseek(fmodule, crypt_off, SEEK_SET);
        wrapped.write(fmodule, modbase.add(crypt_off), crypt_size);
    }

    wrapped.close(fmodule);
    wrapped.close(foldmodule);
    return newmodpath
}

function loadAllDynamicLibrary(app_path: ObjC.Object) {
    var defaultManager = ObjC.classes.NSFileManager.defaultManager();
    var errorPtr = Memory.alloc(Process.pointerSize); 
  errorPtr.writePointer(NULL);
    var filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (var i = 0, l = filenames.count(); i < l; i++) {
        var file_name = filenames.objectAtIndex_(i);
        var file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".framework")) {
            var bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (bundle.isLoaded()) {
                console.log("[frida-ios-dump]: " + file_name + " has been loaded. ");
            } else {
                if (bundle.load()) {
                    console.log("[frida-ios-dump]: Load " + file_name + " success. ");
                } else {
                    console.log("[frida-ios-dump]: Load " + file_name + " failed. ");
                }
            }
        } else if (file_name.hasSuffix_(".bundle") || 
                   file_name.hasSuffix_(".momd") ||
                   file_name.hasSuffix_(".strings") ||
                   file_name.hasSuffix_(".appex") ||
                   file_name.hasSuffix_(".app") ||
                   file_name.hasSuffix_(".lproj") ||
                   file_name.hasSuffix_(".storyboardc")) {
            continue;
        } else {
            var isDirPtr = Memory.alloc(Process.pointerSize);
      isDirPtr.writePointer(NULL);
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            if (isDirPtr.readPointer() == ptr(1)) {
                loadAllDynamicLibrary(file_path);
            } else {
                if (file_name.hasSuffix_(".dylib")) {
                    var is_loaded = 0;
                    for (var j = 0; j < modules.length; j++) {
                        if (modules[j].path.indexOf(file_name) != -1) {
                            is_loaded = 1;
                            console.log("[frida-ios-dump]: " + file_name + " has been dlopen.");
                            break;
                        }
                    } 

                    if (!is_loaded) {
                        if (wrapped.dlopen(allocStr(file_path.UTF8String()), 9)) {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " success. ");
                        } else {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " failed. ");
                        }
                    }
                }
            }
        }
    }
}

function handleMessage(message: any) {
    var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
    loadAllDynamicLibrary(app_path);
    // start dump
    for (var i = 0; i  < modules.length; i++) {
        console.log("start dump " + modules[i].path);
        var result = dumpModule(modules[i].path);
        send({ dump: result, path: modules[i].path});
    }
    send({app: app_path.toString()});
    send({done: "ok"});
    recv(handleMessage);
}

recv(handleMessage);
