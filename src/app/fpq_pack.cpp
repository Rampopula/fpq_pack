#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <string>
#include <algorithm>
#include <memory>
#include <vector>
#include <map>
#include "crc32.h"
#include "version.h"

#ifdef _WIN32
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <windows.h>
    #include "getopt.h"
#else
    #include <getopt.h>
    #include <unistd.h>
#endif

#define VER                 " v" VERSION
#define DEFAULT_SERIAL        "B00B0069"
#define PRINT_CAPTION       do { \
                                uint8_t fpq_x[15] = {0x19,0x0f,0x22,0x54,0x25, \
                                                    0x0d,0x00,0x03,0x0c,0x19, \
                                                    0x0e,0x15,0x52,0x71,0x6f}; \
                                uint8_t fpq_y[15] = {0x36,0x36,0x1a,0x1d,0x1c, \
                                                    0x05,0x0A,0x01,0x00,0x02, \
                                                    0x47,0x0A,0x0A,0x36,0x36}; \
                                int j = 0, i = sizeof(fpq_x) - 5; \
                                while (i--) { std::cout << (char)(fpq_x[j] ^ (fpq_y[j] ^ 0x69)); j++; } \
                            } while(0);

#ifdef _WIN32
    #if defined(__MINGW64__)
        #define PRINT_LONG_CAPTION   PRINT_CAPTION std::cout << VER << " (mingw64 " << __MINGW64_VERSION_MAJOR << "." << __MINGW64_VERSION_MINOR << ")" << std::endl;
    #else
        #define PRINT_LONG_CAPTION   PRINT_CAPTION std::cout << VER << " (unknown)" << std::endl;
    #endif
#else
    #if defined(__GNUC__)
        #define PRINT_LONG_CAPTION   PRINT_CAPTION std::cout << VER << " (gcc " << __GNUC__ << "." << __GNUC_MINOR__ << ")" << std::endl;
    #else
        #define PRINT_LONG_CAPTION   PRINT_CAPTION std::cout << VER << "(unknown)" << std::endl;
    #endif   
#endif


void printHelp() {
    std::cout << "Usage: fpq_pack [-k] [encryption key] [-h] [serial number] [-d] [debug]" << std::endl;
    std::cout << "                [-o] [output file]    [-l] [log file]" << std::endl;
    std::cout << "                [-c] [file]" << std::endl;
    std::cout << "                [-b] [file]" << std::endl;
    std::cout << "                [-s] [file]" << std::endl;
    std::cout << "                [-x] [file]" << std::endl;
    std::cout << "                [-f] [file]" << std::endl << std::endl;
    std::cout << "Used to encrypt and package FPQ firmware into a single file." << std::endl;
    std::cout << "\t -o, \toutput file path" << std::endl;
    std::cout << "\t -k, \tencryption key string" << std::endl;
    std::cout << "\t -d, \tdebug mode on (any value)" << std::endl;
    std::cout << "\t -l, \tlog to file (in debug mode)" << std::endl;
    std::cout << "\t -c, \tfirmware: 'config' path" << std::endl;
    std::cout << "\t -b, \tfirmware: 'u-boot.bin' path" << std::endl;
    std::cout << "\t -x, \tfirmware: 'uImage' path" << std::endl;
    std::cout << "\t -s, \tfirmware: 'media_app_zip.bin' path" << std::endl;
    std::cout << "\t -f, \tfirmware: 'rootfs.cramfs.img' path" << std::endl;
    std::cout << "\t -h, \tfirmware: serial hex string (default: B00B0069)" << std::endl << std::endl;
}

class FPQLog {
    public:
        FPQLog(std::ostream *os = &std::cout) : os(os) { }

        FPQLog &operator=(const FPQLog &log) { this->os = log.os; return *this; }

        template<typename T>
        void operator()(T t) { *os << t; }

        template<typename F, typename T>
        void operator()(F f, T t) { *os << f << t; }

        template<typename F, typename T, typename... Args> 
        void operator()(F f, T t, Args... args) { *os << f << t; this->operator()(args...); }
    private:
        std::ostream *os;
};

struct FPQHeader {
    typedef uint8_t* iterator;
    struct _field { uint32_t size; uint32_t offset; };

    FPQHeader() {
        const std::string magic("~magic~firmware~");
        std::copy(magic.begin(), magic.end(), firmware_magic);   
        std::fill_n(begin() + magic.length(), sizeof(_field) * FileNum_, 0);
    }

    char firmware_magic[16];   
    _field _config;
    _field _serial;
    _field _uboot;
    _field _linux;
    _field _liteos;
    _field _rootfs;

    enum Type { Config = 0, Serial, UBoot, Linux, LiteOS, RootFS, FileNum_ };

    iterator begin(void) { return (uint8_t*)firmware_magic; }

    iterator end(void) { return (uint8_t*)(firmware_magic + blkSize()); }

    void setSize(FPQHeader::Type type, uint32_t size) {
        switch(type) {
            case Config: _config.size = align(size); break;
            case Serial: _serial.size = align(size); break;
            case UBoot: _uboot.size = align(size); break;
            case Linux: _linux.size = align(size); break;
            case LiteOS: _liteos.size = align(size); break;
            case RootFS: _rootfs.size = align(size); break;
            default: break;
        }
    }

    void updateOffsets(void) {
        _config.offset = blkSize();
        _serial.offset = _config.offset + _config.size;
        _uboot.offset = _serial.offset + _serial.size;
        _linux.offset = _uboot.offset + _uboot.size;
        _liteos.offset = _linux.offset + _linux.size;
        _rootfs.offset = _liteos.offset + _liteos.size;
    }

    void dumpLog(FPQLog &log){
        log("****************************************\n");
        log(std::hex, "config size: 0x", _config.size, ", offset: 0x", _config.offset, "\n");
        log("serial size: 0x", _serial.size, ", offset: 0x", _serial.offset, "\n");
        log("uboot size: 0x", _uboot.size, ", offset: 0x", _uboot.offset, "\n");
        log("linux size: 0x", _linux.size, ", offset: 0x", _linux.offset, "\n");
        log("liteos size: 0x", _liteos.size, ", offset: 0x", _liteos.offset, "\n");
        log("rootfs size: 0x", _rootfs.size, ", offset: 0x", _rootfs.offset, "\n");
        log("****************************************\n");
    }
    
    static std::vector<uint8_t> makeSerial(uint32_t serial) {
        std::vector<uint8_t> serialBlk(blkSize());
        union { 
            uint32_t value, crc; 
            uint8_t bytes[sizeof(uint32_t)];
        } _serial { serial };

        auto it = serialBlk.begin();
        while(it != serialBlk.end()) {
            std::copy(_serial.bytes, _serial.bytes + sizeof(uint32_t), it);
            it += sizeof(uint32_t);
        }

        _serial.crc = CRC32_Calculate(serialBlk.data(), blkSize() - sizeof(uint32_t));
        std::copy(_serial.bytes, _serial.bytes + sizeof(uint32_t), it - sizeof(uint32_t));

        return serialBlk;
    }

    static uint32_t align(uint32_t value) {
        return (value % blkSize()) ? value + (blkSize() - (value % blkSize())) : value;
    }

    static uint32_t blkSize(void) {
        return sizeof(FPQHeader);
    }

    static std::string getName(int type) { 
        return fileNames[type]; 
    }

    static const std::vector<std::string> fileNames;

} __attribute__((aligned(512)));
const std::vector<std::string> FPQHeader::fileNames = { "Config","Serial","UBoot","Linux","Liteos","Rootfs" };

class FPQSerial {
    public:
        FPQSerial(const std::string &serialStr) {
            if (!isValid(serialStr)) throw std::runtime_error("Invalid serial number!");
            serial = std::stoul(serialStr, 0, 16);
            this->serialStr = serialStr;
        }
        FPQSerial() : FPQSerial(DEFAULT_SERIAL) { }

        uint32_t get(void) const { return serial; }
        std::string getStr(void) const { return serialStr; }

        FPQSerial &operator=(const FPQSerial &serial) { this->serial = serial.serial; return *this; }

    private:
        bool isValid(const std::string &serial) {
            if (serial.length() != correctLen) return false;

            auto validator = [](char ch) {
                char c = std::tolower(ch);
                if (c < '0' || c > '9')
                    if (c < 'a' || c > 'f') return false;
                return true;
            };

            return std::find_if_not(serial.begin(), serial.end(), validator) == serial.end();
        }

        const size_t correctLen = 8;    // strlen(DEFAULT_SERIAL)
        uint32_t serial;
        std::string serialStr;
};

class FPQFile {
    public:
        enum class OpenMode {RWOpen, RWCreate};

        explicit FPQFile(std::string path, FPQFile::OpenMode mode) : file(NULL), fileSize(0) {
            file = fopen(path.c_str(), (mode == FPQFile::OpenMode::RWCreate) ? "w+b" : "r+b");
            if (!file) throw std::runtime_error(std::string("Unable open '" + path + "'!").c_str());       
            fseek(file, 0L, SEEK_END);
            fileSize = ftell(file);
            fseek(file, 0L, SEEK_SET);
            this->path = path;
        }
        explicit FPQFile(std::string path) : FPQFile(path, FPQFile::OpenMode::RWOpen) {}
        ~FPQFile() { if (file) fclose(file); }

        void setPos(long offset) { fseek(file, offset, SEEK_SET); }

        unsigned size() const { return fileSize; }

        void read(uint8_t *data, unsigned size) {
            if (fread(data, sizeof(uint8_t), size, file) != size)
                throw std::runtime_error(std::string("Unable to read from '" + path + "'!").c_str());
        }

        void write(std::vector<uint8_t> &data) {
            if (fwrite(data.data(), sizeof(uint8_t), data.size(), file) != data.size())
                throw std::runtime_error(std::string("Unable to write to '" + path + "'!").c_str());
        }

    private:
        FILE *file;
        std::string path;
        unsigned fileSize;
};

class FPQEncryptor {
    public:
        FPQEncryptor() { }
        FPQEncryptor(std::string key) {
            if (!key.length() || sizeof(FPQHeader) % key.length())
                throw std::runtime_error("Error! Encryption key length must be a power of 2!");
            this->key = key;
        }
        FPQEncryptor &operator=(const FPQEncryptor &encryptor) { this->key = encryptor.key; return *this; }
        
        std::string getKey(void) const { return key; }

        void encrypt(std::vector<uint8_t> &data) {
            if (!key.length()) return;
            auto it = data.begin();
            while(it != data.end()) {
                std::transform(key.begin(), key.end(), it, it, [](uint8_t a, uint8_t b) { return a ^ b; });
                it += key.length();
            }
        }
    private:
        std::string key;
};


std::string getCurrentDir(void) {
    std::string currentDir;

    #ifdef _WIN32
        TCHAR buffer[MAX_PATH];
        GetCurrentDirectory(MAX_PATH, buffer);
        currentDir = std::string(buffer);
    #else
        auto buffer = std::unique_ptr<char,decltype(&free)>(get_current_dir_name(), free);
        currentDir = std::string(buffer.get());
    #endif

    return currentDir;
}

int32_t main(int argc, char *argv[]) {

    PRINT_LONG_CAPTION;
    if (sizeof(FPQHeader) != 512) throw std::runtime_error("Alignment test not passed!");

    int opt;
    bool debug = false;
    FPQLog log;
    FPQHeader header;
    FPQEncryptor encryptor;
    FPQSerial serial(DEFAULT_SERIAL);
    std::map<int,std::string> files;
    std::string outputPath = getCurrentDir() + std::string("/firmware.bin");
    std::ofstream logFile;

    while((opt = getopt(argc, argv, "d:l:c:b:x:s:f:o:k:h:")) != -1) {
        switch(opt) {
            case 'd': debug = true; break;
            case 'h': serial = FPQSerial(std::string(optarg)); break;
            case 'k': encryptor = FPQEncryptor(std::string(optarg)); break;
            case 'c': files[FPQHeader::Type::Config] = std::string(optarg); break;
            case 'b': files[FPQHeader::Type::UBoot] = std::string(optarg); break;
            case 'x': files[FPQHeader::Type::Linux] =  std::string(optarg); break;
            case 's': files[FPQHeader::Type::LiteOS] =  std::string(optarg); break;
            case 'f': files[FPQHeader::Type::RootFS] = std::string(optarg); break;
            case 'o': outputPath = std::string(optarg); break;
            case 'l':
                if (debug) {
                    log("Logging into file...\n");
                    logFile.open(std::string(optarg));
                    if (!logFile.is_open()) throw std::runtime_error("Unable to create log file!");
                    log = FPQLog(&logFile);
                } 
            break;
            default: printHelp(); return -1; break;
        }
    }

    if (!files.count(FPQHeader::Type::Config)) {
        printHelp();
        log("Error! Config file is not specified!\n");
        return -1;
    }

    if (debug) log("Output file: '", outputPath, "'\n");
    if (debug) log("Using encryption key: '", encryptor.getKey(), "'\n");
    if (debug) {
        log ("Serial number: '", serial.getStr(), "'");
        log (std::hex, " --- [0x", serial.get(),"]\n");
    }

    FPQFile output(outputPath, FPQFile::OpenMode::RWCreate);
    output.setPos(FPQHeader::blkSize());

    for (int i = 0; i < FPQHeader::Type::FileNum_; ++i) {
        if (i == FPQHeader::Type::Serial) {
            if (debug) log(std::dec, FPQHeader::getName(i), " size is ", FPQHeader::blkSize(), " bytes, blocks: 1\n");
            std::vector<uint8_t> fileBlock = FPQHeader::makeSerial(serial.get());
            encryptor.encrypt(fileBlock);
            output.write(fileBlock);
            header.setSize((FPQHeader::Type)i, fileBlock.size());
        }
        else {
            if (!files.count(i)) {
                if (debug) log(FPQHeader::getName(i), " skipping...\n");
                continue;
            }
            
            FPQFile file(files[i]);
            int blkToRead = FPQHeader::align(file.size()) / FPQHeader::blkSize(); 
            if (debug) log(std::dec, FPQHeader::getName(i), " size is ", file.size(), " bytes, blocks: ", blkToRead, "\n");

            for (int blk = 0; blk < blkToRead; ++blk) {
                std::vector<uint8_t> fileBlock(FPQHeader::blkSize());
                int bytesRead = blk * FPQHeader::blkSize();
                int bytesToRead = std::min(file.size() - bytesRead, FPQHeader::blkSize());
        
                file.read(fileBlock.data(), bytesToRead);
                encryptor.encrypt(fileBlock);
                output.write(fileBlock);
            }
            header.setSize((FPQHeader::Type)i, file.size());
        }
    }

    header.updateOffsets();
    if (debug) header.dumpLog(log);

    output.setPos(0L);
    std::vector<uint8_t> headerBlk(header.begin(), header.end());
    encryptor.encrypt(headerBlk);
    output.write(headerBlk);

    log("Packaging done!\n");
    return 0;
}
