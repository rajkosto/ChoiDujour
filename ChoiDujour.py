import os
import sys
import struct
import json
import binascii
import gzip
import urllib2
from StringIO import StringIO
import subprocess
import hashlib
import tempfile
import shutil
import platform

if platform.system() == 'Windows':
    import win32con
    import win32api

programName = 'ChoiDujour'
programVersion = '1.1.0'

extension = '.exe' if platform.system() == 'Windows' else ''

toolspath = os.environ['PATH'].split(os.pathsep)
if getattr( sys, 'frozen', False ):
    toolspath = [sys._MEIPASS] + toolspath
else:
    toolspath = [os.path.dirname(os.path.realpath(__file__))] + toolspath

def find_tool(name):
    for dir in toolspath:
        if os.path.exists(os.path.join(dir, name + extension)):
            return os.path.join(dir, name + extension)
    sys.exit('Required tool ' + name + ' is missing!')

hactool = find_tool('hactool')
kip1decomp = find_tool('kip1decomp')
seven7a = find_tool('7za')

for toolPath in [hactool,kip1decomp,seven7a]:
    if not os.path.exists(toolPath):
        sys.exit('Required tool ' + os.path.basename(toolPath) + ' is missing!')

def print_welcome():
    print('')
    print(programName + ' ' + programVersion + ' by rajkosto')
    print('uses hactool by SciresM (https://github.com/SciresM/hactool)')
    print('visit https://switchtools.sshnuke.net for updates and more Switch stuff!')
    print('')

def print_usage():
    print_welcome()
    print('Usage:')
    print('ChoiDujour [--help] [--dev] [--keyset=path/to/keys.txt] [--noexfat] [--nossl]   [--fspatches=nocmac,nogc] [--intype=xci/nca/romfs/hfs0] firmwareSrc')
    print('')
    print('Parameters: ')
    print('--help\t\tdisplay this usage message')
    print('--dev\t\ttell hactool to use dev instead of production keys')
    print('--keyset=path\toverride default hactool keys txt file path')
    print('--noexfat\talways generate normal BCPKG2/FS.kip1 (no exfat support)')
    print('--nossl\t\tuse http instead of https protocol for web requests')
    print('--fspatches\tcomma separated list of patches to apply to generated FS.kip1')
    print('--intype=type\tfirmware package file type (Ignored if firmwareSrc is a folder)')
    print('firmwareSrc\tpath to source firmware package file or folder')
    print('')

hackeyspath = ''
hacisDev = False
try_exfat = True
http_only = False
wanted_patches = ['nocmac', 'nogc']

myParams = []
inputFiles = []
inFileType = ''

for i in xrange(1,len(sys.argv)):
    currArg = sys.argv[i]
    if currArg.startswith('--'):
        myParams += [currArg]
    else:
        inputFiles += [currArg]

try:
    for currParam in myParams:
        if (currParam == '-h') or (currParam == '--help'):
            print_usage()
            sys.exit()
        elif currParam == '--dev':
            hacisDev = True
        elif currParam == '--noexfat':
            try_exfat = False
        elif currParam == '--nossl':
            http_only = True
        elif currParam.startswith('--keyset='):
            hackeyspath = currParam[9:]
        elif currParam.startswith('--intype='):
            inFileType = currParam[9:].lower()
            validTypes = ['nca', 'xci', 'romfs', 'hfs0']
            if inFileType not in validTypes:
                sys.exit('Invalid input file type ' + inFileType + ' (supported: ' + ",".join(validTypes) + ')')
        elif currParam.startswith('--fspatches='):
            selectedPatchesStr = currParam[12:].strip().lower()
            wanted_patches = []
            if len(selectedPatchesStr) > 0:
                for patchName in selectedPatchesStr.split(','):
                    wanted_patches += [patchName.strip()]
                wanted_patches.sort()
        else:
            sys.exit('Unknown parameter specified: ' + currParam)

    if len(inputFiles) != 1:
        if len(inputFiles) == 0:
            sys.exit('Please specify input firmware file/folder!')
        else:
            sys.exit('Only one input firmware file/folder argument is allowed, you gave ' + str(len(inputFiles)))
except SystemExit, e:
    if e.code is not None:
        print_usage()
    raise

if len(hackeyspath) == 0:
    hackeyspath = os.path.expanduser('~/.switch/')
    if hacisDev:
        hackeyspath += 'dev.keys'
    else:
        hackeyspath += 'prod.keys'

if not os.path.exists(hackeyspath):
    sys.exit('hactool keys file ' + hackeyspath + " doesn't exist!")

def hash_bytestr_iter(bytesiter, hasher, ashexstr=False):
    for block in bytesiter:
        hasher.update(block)
    return (hasher.hexdigest() if ashexstr else hasher.digest())

def file_as_blockiter(afile, blocksize=65536):
    with afile:
        block = afile.read(blocksize)
        while len(block) > 0:
            yield block
            block = afile.read(blocksize)

def deunicodify_hook(pairs):
    new_pairs = []
    for key, value in pairs.iteritems():
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        new_pairs.append((key, value))
    return dict(new_pairs)

def get_sha256_file_digest(fname):
    return hash_bytestr_iter(file_as_blockiter(open(fname, 'rb')), hashlib.sha256(), ashexstr=True)

def fetch_url_bytes(url, gzipped=True):
    if http_only and url.startswith('https:'):
        url = 'http:' + url[6:]

    print('Making a request to URL ' + url)
    request = urllib2.Request(url)
    if gzipped:
        request.add_header('Accept-encoding', 'gzip')

    response = urllib2.urlopen(request)
    if response.info().get('Content-Encoding') == 'gzip':
        buf = StringIO(response.read())
        f = gzip.GzipFile(fileobj=buf)
        return f.read()
    else:
        return response.read()

def download_large_file(url, outFilename):
    if http_only and url.startswith('https:'):
        url = 'http:' + url[6:]

    print('Downloading file from URL ' + url)
    remote_file = urllib2.urlopen(url)
    total_size = None
    header = None
    try:
        total_size = remote_file.info().getheader('Content-Length').strip()
        header = True
    except AttributeError:
        header = False # a response doesn't always include the "Content-Length" header

    if header:
        total_size = int(total_size)

    with open(outFilename, 'wb') as outputFile:
        bytes_so_far = 0
        while True:
            buffer = remote_file.read(128*1024)
            if not buffer:
                sys.stdout.write('\n')
                sys.stdout.flush()
                return [bytes_so_far, total_size]

            bytes_so_far += len(buffer)
            outputFile.write(buffer)
            if not header:
                total_size = bytes_so_far # unknown size

            percent = float(bytes_so_far) / total_size
            percent = round(percent*100, 2)
            sys.stdout.write("Downloaded %d of %d bytes (%0.2f%%)\r" % (bytes_so_far, total_size, percent))
            sys.stdout.flush()

hacargs = []
if hacisDev:
    hacargs += ['--dev']
hacargs += ['--keyset=' + hackeyspath]

def call_hactool(moreArgs):
    totalArgs = [hactool] + hacargs + moreArgs
    pipes = subprocess.Popen(totalArgs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    std_out, std_err = pipes.communicate()

    if pipes.returncode != 0:
        err_msg = "%s. Code: %s" % (std_err.strip(), pipes.returncode)
        raise Exception(err_msg)

    elif len(std_err):
       

    return std_out

def realtime_run(totalArgs):
    process = subprocess.Popen(totalArgs, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    while True:
        nextline = process.stdout.readline()
        if nextline == '' and process.poll() is not None:
            break
        sys.stdout.write(nextline)
        sys.stdout.flush()

    output = process.communicate()[0]
    exitCode = process.returncode

    if (exitCode == 0):
        return output
    else:
        raise subprocess.CalledProcessError(exitCode, " ".join(totalArgs), output)

def find_line_starting(strarray, prefix):
    for line in strarray:
        if line.startswith(prefix):
            return line[len(prefix):].lstrip()

    return None

def set_file_attributes(filePath, attrStr):
    if platform.system() != 'Windows':
        return
    attrStr = attrStr.upper()
    winAttrs = 0x0
    if (len(attrStr) == 0) or (attrStr == 'N'):
        winAttrs = win32con.FILE_ATTRIBUTE_NORMAL

    for c in attrStr:
        if c == 'S':
            winAttrs |= win32con.FILE_ATTRIBUTE_SYSTEM
        elif c == 'H':
            winAttrs |= win32con.FILE_ATTRIBUTE_HIDDEN
        elif c == 'R':
            winAttrs |= win32con.FILE_ATTRIBUTE_READONLY
        elif c == 'A':
            winAttrs |= win32con.FILE_ATTRIBUTE_ARCHIVE
        elif c == 'T':
            winAttrs |= win32con.FILE_ATTRIBUTE_TEMPORARY

    win32api.SetFileAttributes(filePath, winAttrs)

class FileInfo(object):
    path = ""
    attrs = ""

    def __init__(self, path, attrs):
        self.path = path
        self.attrs = attrs

class NcaInfo(FileInfo):
    titleId = ""
    contentType = ""

    def __init__(self, path, attrs, titleId, contentType):
        self.path = path
        self.attrs = attrs
        self.titleId = titleId
        self.contentType = contentType

ncas = {}
titles = {}

class FirmwarePackage(object):
    titleId = ""
    ncaId = None
    bctBytes = []
    pkg1Bytes = []
    pkg2Bytes = []

    def load(self, baseDir, subDir):
        myDir = os.path.join(baseDir, self.titleId)
        os.makedirs(myDir)
        call_hactool(["-x", "--intype=nca", "--romfsdir="+myDir, ncas[self.ncaId].path])

        bctFilename = os.path.join(myDir,subDir,"bct")
        pkg1Filename = os.path.join(myDir,subDir,"package1")
        pkg2Filename = os.path.join(myDir,subDir,"package2")

        with open(bctFilename, 'rb') as bctFile:
            self.bctBytes = bytearray(bctFile.read())
        with open(pkg1Filename, 'rb') as pkg1File:
            self.pkg1Bytes = bytearray(pkg1File.read())
        with open(pkg2Filename, 'rb') as pkg2File:
            self.pkg2Bytes = bytearray(pkg2File.read())

        bctLen = len(self.bctBytes)
        pkg1Len = len(self.pkg1Bytes)

        if bctLen > 0x4000:
            raise RuntimeError("Unpacked BCT too large!")
        else:
            self.bctBytes[0x210] = 0x77; #corrupt the PubKey so the console doesn't boot normally
            self.bctBytes += "\0" * (0x4000 - bctLen)

        if pkg1Len > 0x40000:
            raise RuntimeError("Unpacked package1 too large!")
        else:
            self.pkg1Bytes += "\0" * (0x40000 - pkg1Len)

        return pkg2Filename

#copied verbatim from https://github.com/reswitched/loaders/blob/master/nxo64.py
def kip1_blz_decompress(compressed):
    compressed_size, init_index, uncompressed_addl_size = struct.unpack('<III', compressed[-0xC:])
    decompressed = compressed[:] + '\x00' * uncompressed_addl_size
    decompressed_size = len(decompressed)
    if len(compressed) != compressed_size:
        assert len(compressed) > compressed_size
        compressed = compressed[len(compressed) - compressed_size:]
    if not (compressed_size + uncompressed_addl_size):
        return ''
    compressed = map(ord, compressed)
    decompressed = map(ord, decompressed)
    index = compressed_size - init_index
    outindex = decompressed_size
    while outindex > 0:
        index -= 1
        control = compressed[index]
        for i in xrange(8):
            if control & 0x80:
                if index < 2:
                    raise ValueError('Compression out of bounds!')
                index -= 2
                segmentoffset = compressed[index] | (compressed[index+1] << 8)
                segmentsize = ((segmentoffset >> 12) & 0xF) + 3
                segmentoffset &= 0x0FFF
                segmentoffset += 2
                if outindex < segmentsize:
                    raise ValueError('Compression out of bounds!')
                for j in xrange(segmentsize):
                    if outindex + segmentoffset >= decompressed_size:
                        raise ValueError('Compression out of bounds!')
                    data = decompressed[outindex+segmentoffset]
                    outindex -= 1
                    decompressed[outindex] = data
            else:
                if outindex < 1:
                    raise ValueError('Compression out of bounds!')
                outindex -= 1
                index -= 1
                decompressed[outindex] = compressed[index]
            control <<= 1
            control &= 0xFF
            if not outindex:
                break
    return ''.join(map(chr, decompressed))
#end of code copied from https://github.com/reswitched/loaders/blob/master/nxo64.py

class InMemoryFile(object):
    contents = ""
    def write(self, moredata):
        self.contents += moredata

class KipSegment(object):
    dstOff = 0
    decompSz = 0
    compSz = 0
    attribute = 0
    datas = ""

class KipHeader(object):
    name = ""
    titleId = 0
    processCategory = 0
    mainThreadPriority = 0
    defaultCpuId = 0
    unk = 0
    flags = 0
    segments = []
    capabilities = []

    def load(self, srcFile):
        magicBytes = srcFile.read(4)
        magic = struct.unpack('>I', magicBytes)[0]
        if magic != 0x4B495031:
            raise ValueError('KIP1 invalid magic')
        
        headerBytes = srcFile.read(32-4)
        (self.name, self.titleId, self.processCategory, self.mainThreadPriority, self.defaultCpuId, self.unk, self.flags) = struct.unpack('<12sQIBBBB', headerBytes)

        self.segments = []
        for i in xrange(6):
            headerBytes = srcFile.read(16)
            newSegment = KipSegment()
            (newSegment.dstOff, newSegment.decompSz, newSegment.compSz, newSegment.attribute) = struct.unpack('<IIII', headerBytes)
            self.segments += [newSegment]

        headerBytes = srcFile.read(128)
        caps = struct.unpack('<32I', headerBytes)
        self.capabilities = []
        for cap in caps:
            self.capabilities += [cap]

        for i in xrange(6):
            self.segments[i].datas = srcFile.read(self.segments[i].compSz)

    def save(self, dstFile):
        dstFile.write(struct.pack('>I', 0x4B495031))
        dstFile.write(struct.pack('<12sQIBBBB', self.name, self.titleId, self.processCategory, self.mainThreadPriority, self.defaultCpuId, self.unk, self.flags))
        for seg in self.segments:
            dstFile.write(struct.pack('<IIII', seg.dstOff, seg.decompSz, seg.compSz, seg.attribute))
        for cap in self.capabilities:
            dstFile.write(struct.pack('<I', cap))

        for seg in self.segments:
            if seg.compSz != 0:
                dstFile.write(seg.datas)

    def decompress(self):
        for i, seg in enumerate(self.segments):
            if i >= 3:
                break

            if (self.flags & (1 << i)) == 0:
                continue

            decompData = kip1_blz_decompress(seg.datas)
            seg.datas = decompData
            seg.compSz = len(decompData)
        
        self.flags = self.flags & 0xF8 #nothing is compressed anymore

    def getContents(self):
        dstFile = InMemoryFile()
        self.save(dstFile)
        return dstFile.contents


print_welcome()
upd_dir = inputFiles[-1]
if not os.path.exists(upd_dir):
    sys.exit('Input source firmware package path ' + upd_dir + " doesn't exist!")

if os.path.isdir(upd_dir):
    print('Using source firmware files from folder ' + upd_dir)
else:
    updName, updExt = os.path.splitext(upd_dir)
    if len(inFileType) == 0:
        if updExt.lower() == '.xci':
            inFileType = updExt.lower()[1:]
        else:
            with open(upd_dir, 'rb') as updFile:
                magicBytes = updFile.read(4)
                if (len(magicBytes) == 4) and (magicBytes == 'HFS0'):
                    inFileType = 'hfs0'

            if len(inFileType) == 0:
                sys.exit("Don't know the type of input file " + upd_dir + " please specify it with --intype parameter")

    targetFolder = updName + '_update'
    print('Extracting files from ' + upd_dir + ' to folder ' + targetFolder)
    if not os.path.exists(targetFolder):
        os.makedirs(targetFolder)

    theargs = ['--intype='+inFileType]
    if inFileType == 'nca':
        theargs += ['--romfsdir='+targetFolder]
    elif inFileType == 'xci':
        theargs += ['--updatedir='+targetFolder]
    else:
        theargs += ['--outdir='+targetFolder]

    theargs += [upd_dir]
    call_hactool(theargs)
    upd_dir = targetFolder

numMeta = 0
numData = 0

upd_dir_abs = os.path.abspath(upd_dir)
for currDir, subdirs, files in os.walk(upd_dir_abs):
    subdirs.sort()
    files.sort()
    for filename in files:
        currFile = os.path.join(currDir, filename)
        fileIsNca = False
        if filename.endswith(".nca") or (filename == "00" and currDir.endswith(".nca")):
            fileIsNca = True

        if not fileIsNca:
            print('file ' + currFile + ' not a NCA, skipping')
            continue

        
        ncaId = get_sha256_file_digest(currFile)
        ncaId = ncaId[:len(ncaId)/2]

        titleId = find_line_starting(ncaInfoLines, "Title ID:")
        contentType = find_line_starting(ncaInfoLines, "Content Type:")

        if (titleId is None) or (contentType is None):
            sys.exit(currFile + ' is missing Title ID or Content Type in hactool output!')

        ncas[ncaId] = NcaInfo(currFile, '', titleId, contentType)
        #print(ncaId + ' = NcaInfo(' + ncas[ncaId].path + ' , ' + ncas[ncaId].titleId + ' , ' + ncas[ncaId].contentType + ')')
        if contentType == "Meta":
            numMeta = numMeta + 1
        else:
            numData = numData + 1
            if titleId not in titles:
                titles[titleId] = ncaId

print('Found ' + str(numMeta) + ' meta and ' + str(numData) + ' data NCAs in ' + upd_dir_abs)
sysVerNcaId = titles.get('0100000000000809')
if sysVerNcaId is None:
    sys.exit('System version NCA not found!')

tempDirName = ''
try:
    sysVerNcaPath = ncas[sysVerNcaId].path
    tempDirName = tempfile.mkdtemp()
    call_hactool(["-x", "--intype=nca", "--romfsdir="+tempDirName, sysVerNcaPath])
    
    versionNumbers = [0,0,0,0]
    versionPlatform = ''
    versionHash = ''
    versionStr = ''
    versionDescr = ''
    with open(os.path.join(tempDirName,"file"), 'rb') as versionFile:
        versionBytes = versionFile.read()
        versionNumbers = struct.unpack('BBBB', versionBytes[0:4])
        versionPlatform = versionBytes[0x8:0x28].split('\0', 1)[0]
        versionHash = versionBytes[0x28:0x68].split('\0', 1)[0]
        versionStr = versionBytes[0x68:0x80].split('\0', 1)[0]
        versionDescr = versionBytes[0x80:].split('\0', 1)[0]

    regenVersionStr = str(versionNumbers[0]) + "." + str(versionNumbers[1]) + "." + str(versionNumbers[2]) + "." + str(versionNumbers[3])
    if not regenVersionStr.startswith(versionStr):
        sys.exit('Invalid system version in firmware!')

    print("Package contains '" + versionPlatform + "' firmware version '" + versionStr + "' (" + regenVersionStr + ")" + " = " + versionDescr + "(hash : " + versionHash + ')')
    
    stdpkg2titles = ['0100000000000819', '010000000000081a']
    exfpkg2titles = ['010000000000081b', '010000000000081c']

    normalPkg = FirmwarePackage()
    safePkg = FirmwarePackage()

    if try_exfat:
        normalPkg.titleId = exfpkg2titles[0]
        normalPkg.ncaId = titles.get(normalPkg.titleId)
        safePkg.titleId = exfpkg2titles[1]
        safePkg.ncaId = titles.get(safePkg.titleId)

    if (normalPkg.ncaId is not None) and (normalPkg.ncaId.lower() == '3b7cd379e18e2ee7e1c6d0449d540841'): #bogus exFAT in 1.0.0
        normalPkg.ncaId = None

    if normalPkg.ncaId is None:
        normalPkg.titleId = stdpkg2titles[0]
        normalPkg.ncaId = titles.get(normalPkg.titleId)
    if safePkg.ncaId is None:
        safePkg.titleId = stdpkg2titles[1]
        safePkg.ncaId = titles.get(safePkg.titleId)

    if normalPkg.ncaId is None:
        sys.exit('Missing Normal Firmware Package! (TitleID: ' + normalPkg.titleId + ')')
    if safePkg.ncaId is None:
        sys.exit('Missing SAFE Firmware Package! (TitleID: ' + safePkg.titleId + ')')

    firmwareIsExFAT = normalPkg.titleId in exfpkg2titles
    print('Using TitleID ' + normalPkg.titleId + ' for Normal firmware package')
    pkg2path = normalPkg.load(tempDirName, versionPlatform.lower())
    print('Using TitleID ' + safePkg.titleId + ' for SAFE firmware package')
    safePkg.load(tempDirName, versionPlatform.lower())

    boot0 = bytearray()
    boot0 += normalPkg.bctBytes
    boot0 += safePkg.bctBytes
    boot0 += normalPkg.bctBytes
    boot0 += safePkg.bctBytes
    boot0 += "\0" * 0xF0000
    boot0 += normalPkg.pkg1Bytes
    boot0 += normalPkg.pkg1Bytes
    assert len(boot0) == 0x180000

    boot1 = bytearray()
    boot1 += safePkg.pkg1Bytes
    boot1 += safePkg.pkg1Bytes
    assert len(boot1) == 0x80000

    pkg2_1 = bytearray()
    pkg2_1 += "\0" * 0x4000
    pkg2_1 += normalPkg.pkg2Bytes
    pkg2_1 += "\0" * (0x800000 - len(pkg2_1))
    assert len(pkg2_1) == 0x800000

    pkg2_2 = pkg2_1

    pkg2_3 = bytearray()
    pkg2_3 += "\0" * 0x4000
    pkg2_3 += safePkg.pkg2Bytes
    pkg2_3 += "\0" * (0x800000 - len(pkg2_3))
    assert len(pkg2_3) == 0x800000

    pkg2_4 = pkg2_3

    prevDir = os.getcwdu()
    call_hactool(["-x", "--intype=package2", "--outdir="+tempDirName, pkg2path])
    call_hactool(["-x", "--intype=ini1", "--outdir="+tempDirName, os.path.join(tempDirName,"INI1.bin")])
    os.chdir(tempDirName)
    compFSkipName = "FS.kip1"    
    compFSKipHash = get_sha256_file_digest(compFSkipName)
    compFSKipHash = compFSKipHash[:len(compFSKipHash)/2].lower()

    print('Decompressing ' + compFSkipName + ' from TitleID ' + normalPkg.titleId + ' hash ' + compFSKipHash)
    kipdata = KipHeader()
    with open(compFSkipName, 'rb') as srcKipFile:        
        kipdata.load(srcKipFile)    
    kipdata.decompress()
    kipdata = kipdata.getContents()
    
    fsPatches = {}
    fsPatchesJsonBytes = fetch_url_bytes('https://switchtools.sshnuke.net/firmware/fs_patches.json')
    fsPatches = json.loads(fsPatchesJsonBytes, object_hook=deunicodify_hook)

    fsVersions = fsPatches['versions']
    if compFSKipHash not in fsVersions:
        sys.exit('Unknown ' + compFSkipName + ' hash: ' + compFSKipHash + ' This firmware is not supported(yet?)')

    fsVersionInfo = fsVersions[compFSKipHash]
    fsVersionName = fsVersionInfo['name']
    fsVersionPatches = fsVersionInfo['patches']

    finalFilenameArr = [os.path.splitext(fsVersionName)[0]]
    for wntpatch in wanted_patches:
        if wntpatch not in fsVersionPatches:
            sys.exit("Requested patch '" + wntpatch + "' currently not available for '" + fsVersionName + "', cannot continue!")

        fsPatchName = fsVersionPatches[wntpatch]
        if not fsPatchName:
            print("Patch '" + wntpatch + "' does not need to be applied on '" + fsVersionName + "', skipping")
            continue

        print("Applying patch '" + wntpatch + "' on '" + fsVersionName + "' using definition '" + fsPatchName + "'...")
        fsPatchData = fsPatches['patches'][fsPatchName]
        for offsetStr, dataArr in fsPatchData.items():
            offsetNum = int(offsetStr, 0)
            neededBytes = binascii.unhexlify(dataArr[0].replace(' ', ''))
            targetBytes = binascii.unhexlify(dataArr[1].replace(' ', ''))

            sourceBytes = bytes(kipdata[offsetNum:offsetNum+len(neededBytes)])
            if sourceBytes != neededBytes:
                sys.exit("Data at offset " + hex(offsetNum) + ' ( ' + binascii.hexlify(sourceBytes) + ' ) does not match expected ( ' + binascii.hexlify(neededBytes) + ' )!')

            kipdata = kipdata[:offsetNum] + targetBytes + kipdata[offsetNum+len(targetBytes):]
            sourceBytes = bytes(kipdata[offsetNum:offsetNum+len(targetBytes)])
            if sourceBytes != targetBytes:
                sys.exit("Data at offset " + hex(offsetNum) + ' ( ' + binascii.hexlify(sourceBytes) + ' ) does not match expected ( ' + binascii.hexlify(targetBytes) + ' )!')
            
            print('Written to ' + hex(offsetNum) + ': ' + binascii.hexlify(sourceBytes).upper())

        finalFilenameArr += [wntpatch]

    
    fsPatchTarget = '_'.join(finalFilenameArr) + os.path.splitext(fsVersionName)[1]
    with open(fsPatchTarget, 'wb') as dstPatchedFile:
        dstPatchedFile.write(kipdata)

    fsPatchedSize = os.stat(fsPatchTarget).st_size
    print('Compressing ' + fsPatchTarget + '...')
    realtime_run([kip1decomp, "c", fsPatchTarget, fsPatchTarget])
    print('Compressed ' + fsPatchTarget + ' from ' + str(fsPatchedSize) + ' to ' + str(os.stat(fsPatchTarget).st_size) + ' bytes')
    os.chdir(prevDir)

    outDirName = versionPlatform + '-' + versionStr
    if firmwareIsExFAT:
        outDirName += '_exfat'

    shutil.rmtree(outDirName, ignore_errors=True)
    os.makedirs(outDirName)
    os.chdir(outDirName)

    print('Writing microSD files')
    microsdDir = "microSD"
    os.mkdir(microsdDir)
    shutil.move(os.path.join(tempDirName, fsPatchTarget), os.path.join(microsdDir, fsPatchTarget))
    with open(os.path.join(microsdDir, 'hekate_ipl.ini'),'w') as hekateFile:
        stockSectionName = 'stock'
        fsSectionName = 'FS_' + versionStr.replace(".","")
        if firmwareIsExFAT:
            fsSectionName += '-exfat'
        if len(finalFilenameArr) > 1:
            fsSectionName += '_' + '_'.join(finalFilenameArr[1:])
            if 'nogc' in finalFilenameArr[1:]:
                stockSectionName += '-POTENTIALLY_UNSAFE_FOR_GC_READER'

        hekateFile.write("[" + stockSectionName + "]\n")
        hekateFile.write("[" + fsSectionName + "]\n")
        hekateFile.write("kip1=" + fsPatchTarget + "\n")
        hekateFile.write("\n")

    jayson = {}
    try:
        patchesJsonUrl = 'https://switchtools.sshnuke.net/firmware/'+versionHash
        if firmwareIsExFAT:
            patchesJsonUrl += '_exfat'
        patchesJsonUrl += '.json'

        jayson = json.loads(fetch_url_bytes(patchesJsonUrl), object_hook=deunicodify_hook)
    except urllib2.HTTPError, e:
        if e.code != 404:
            raise
        else:
            sys.exit('No index on server for ' + outDirName + '. This firmware is not supported(yet?)')

    for ncaId in jayson['ncas']:
        ncaDict = jayson['ncas'][ncaId]
        ncaInfo = NcaInfo(ncaDict['path'], ncaDict['attrs'], ncaDict['titleId'], ncaDict['contentType'])
        jayson['ncas'][ncaId] = ncaInfo
        #print('NCA: ' + ncaId + ' = ' + ncaInfo.titleId + ':' + ncaInfo.contentType)

    for fileHash in jayson['files']:
        fileDict = jayson['files'][fileHash]
        fileInfo = FileInfo(fileDict['path'], fileDict['attrs'])
        jayson['files'][fileHash] = fileInfo
        #print('File: ' + fileHash + ' = ' + fileInfo.path + ':' + fileInfo.attrs)

    missingNcas = 0
    for ncaId in jayson['ncas']:
        if ncaId not in ncas:
            missingNcas += 1
            ncaInfo = jayson['ncas'][ncaId]
            print('Missing NCA for ' + ncaInfo.contentType+':'+ncaInfo.titleId + '!')

    if missingNcas > 0:
        sys.exit('Missing ' + str(missingNcas) + ' required NCAs in firmware')

    archivedFilesPath = ''
    archiveInfo = jayson.get('archive')
    if archiveInfo is not None:
        downloadsFolder = os.path.join(tempfile.gettempdir(), programName)
        if not os.path.exists(downloadsFolder):
            os.mkdir(downloadsFolder)

        archivedFilesPath = os.path.join(downloadsFolder, archiveInfo['url'].split("/")[-1])
        needsDownload = True
        neededHash = archiveInfo['hash']
        if os.path.exists(archivedFilesPath):
            print('Needed archive already downloaded, checking hash...')
            archiveHash = get_sha256_file_digest(archivedFilesPath)[0:len(neededHash)]
            if archiveHash.lower() != neededHash.lower():
                print('Existing file hash mismatch, deleting and redownloading')
            else:
                print('Downloaded file hash is ' + archiveHash + ' as expected')
                needsDownload = False

        if needsDownload:
            download_large_file(archiveInfo['url'], archivedFilesPath)
            archiveHash = get_sha256_file_digest(archivedFilesPath)[0:len(neededHash)]
            if archiveHash.lower() != neededHash.lower():
                print('Downloaded file hash mismatch, exiting!')
                sys.exit('Downloaded file hash ' + archiveHash + ' expected ' + neededHash)

    print('Writing partition images')
    with open('BOOT0.bin','wb') as boot0file:
        boot0file.write(boot0)
    with open('BOOT1.bin','wb') as boot1file:
        boot1file.write(boot1)
    with open('BCPKG2-1-Normal-Main.bin','wb') as bcpkg2_1file:
        bcpkg2_1file.write(pkg2_1)
    with open('BCPKG2-2-Normal-Sub.bin','wb') as bcpkg2_2file:
        bcpkg2_2file.write(pkg2_2)
    with open('BCPKG2-3-SafeMode-Main.bin','wb') as bcpkg2_3file:
        bcpkg2_3file.write(pkg2_3)
    with open('BCPKG2-4-SafeMode-Sub.bin','wb') as bcpkg2_4file:
        bcpkg2_4file.write(pkg2_4)

    dirsToMake = []
    for dirPath in jayson['dirs']:
        dirsToMake += [dirPath]

    for dirPath in sorted(dirsToMake):
        #print('Making dir ' + dirPath)
        os.makedirs(dirPath)
        set_file_attributes(dirPath, jayson['dirs'][dirPath])

    for ncaId in jayson['ncas']:
        srcInfo = ncas[ncaId]
        targetInfo = jayson['ncas'][ncaId]
        print('Writing NCA ' + targetInfo.contentType + ':' + targetInfo.titleId + ' to ' + targetInfo.path)
        shutil.copyfile(srcInfo.path, targetInfo.path)
        set_file_attributes(targetInfo.path, targetInfo.attrs)

    if archivedFilesPath != '':
        realtime_run([seven7a, "x", archivedFilesPath, "-aoa"])

    for fileHash in jayson['files']:
        fileInfo = jayson['files'][fileHash]
        filePath = fileInfo.path
        print('Verifying file ' + filePath)
        fileNewHash = get_sha256_file_digest(filePath)[0:len(fileHash)]
        if fileNewHash.lower() != fileHash.lower():
            print('Invalid hash, cannot continue!')
            sys.exit('Extracted file ' + filePath + ' has hash ' + fileNewHash + ' , expected ' + fileHash)
        set_file_attributes(filePath, fileInfo.attrs)

    print('All files verified! Prepared firmware update is in folder ' + os.getcwd())
finally:
    if tempDirName != '':
        shutil.rmtree(tempDirName, ignore_errors=True)
