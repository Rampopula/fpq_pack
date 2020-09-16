#include <iostream>
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

#define VER             	" v" VERSION
#define DEFAULT_SERIAL		"B00B0069"
#define PRINT_CAPTION   	do { \
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
    std::cout << "Usage: fpq_pack [-k] [value] [-d] [value]" << std::endl;
    std::cout << "                [-o] [file]  [-c] [file]" << std::endl;
    std::cout << "                [-b] [file]  [-x] [file]" << std::endl;
    std::cout << "                [-s] [file]  [-f] [file]" << std::endl << std::endl;
    std::cout << "Used to encrypt and package FPQ firmware into a single file." << std::endl;
    std::cout << "\t -o, \toutput file path" << std::endl;
    std::cout << "\t -k, \tencryption key string" << std::endl;
    std::cout << "\t -d, \tdebug mode on (any value)" << std::endl;
    std::cout << "\t -c, \tfirmware: 'config' path" << std::endl;
    std::cout << "\t -b, \tfirmware: 'u-boot.bin' path" << std::endl;
    std::cout << "\t -x, \tfirmware: 'uImage' path" << std::endl;
    std::cout << "\t -s, \tfirmware: 'media_app_zip.bin' path" << std::endl;
    std::cout << "\t -f, \tfirmware: 'rootfs.cramfs.img' path" << std::endl << std::endl;
	std::cout << "\t -h, \tfirmware: serial hex string (default: B00B0069)" << std::endl;
}

struct FPQHeader {
    struct _field { uint32_t size; uint32_t offset; };

    FPQHeader() { 
		std::memset((uint8_t*)&_config, 0x00, sizeof(_config) * 5);
		std::memcpy(firmware_magic, "~magic~firmware~", sizeof(firmware_magic));
	}

    char firmware_magic[16];
    _field _config;
	_field _serial;
    _field _uboot;
    _field _linux;
    _field _liteos;
    _field _rootfs;

    enum Type { Config = 0, Serial, UBoot, Linux, LiteOS, RootFS, FileNum_ };

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
    
	static void makeSerial(uint32_t serial, std::vector<uint8_t> &buf) {
		uint32_t *serialData;
		unsigned i, serialSize = buf.size() - sizeof(uint32_t);
		for (i = 0; i < serialSize; i+=sizeof(serial)) {
			serialData = (uint32_t*)(buf.data() + i);
			*serialData = serial;
		}
		serialData = (uint32_t*)(buf.data() + i);
		*serialData = CRC32_Calculate((uint8_t*)buf.data(), serialSize);
	}

    static uint32_t align(uint32_t value) {
        return (value % blkSize()) ? value + (blkSize() - (value % blkSize())) : value;
    }

    static uint32_t blkSize(void) {
        return sizeof(FPQHeader);
    }

} __attribute__((aligned(512)));

class FPQFile {
    public:
        enum class OpenMode {RWOpen, RWCreate};

        explicit FPQFile(std::string path, FPQFile::OpenMode mode) : file(NULL), fileSize(0) {
            file = fopen(path.c_str(), (mode == FPQFile::OpenMode::RWCreate) ? "w+b" : "r+b");
            if (file) {
                fseek(file, 0L, SEEK_END);
                fileSize = ftell(file);
                fseek(file, 0L, SEEK_SET);
            }
        }
        explicit FPQFile(std::string path) : FPQFile(path, FPQFile::OpenMode::RWOpen) {}
        ~FPQFile() { if (file) fclose(file); }

        bool isOpened(void) const { return file ? true : false; }

        void seek(long offset) { fseek(file, offset, SEEK_SET); }

        unsigned size() const { return fileSize; }

        bool read(uint8_t *data, unsigned size) {
            return (fread(data, sizeof(uint8_t), size, file) == size) ? true : false;
        }

        bool write(uint8_t *data, unsigned size) {
            return (fwrite(data, sizeof(uint8_t), size, file) == size) ? true : false;
        }
    private:
        FILE *file;
        unsigned fileSize;
};

class FPQEncryptor {
    public:
        FPQEncryptor() { }
        FPQEncryptor(std::string key) : key(key) { }
        FPQEncryptor &operator=(std::string const &key) { this->key = key; return *this; }

        bool isKeyValid(void) const {
            if (!key.length()) return false;
            return (sizeof(FPQHeader) % key.length()) ? false : true;
        }

        void encrypt(std::vector<uint8_t> &data) {
            if (!isKeyValid()) return;
            std::vector<uint8_t>::iterator it = data.begin();
            for (unsigned i = 0; i < (data.size() / key.length()); ++i) {
				#if 0
                if (!isEncodingAvailable(it)) {
                    it += key.length();
                    continue;
                }
				#endif
                for (auto keyByte : key) { 
                    *it ^= keyByte; ++it;
                }
            }
        }
    private:
        bool isEncodingAvailable(std::vector<uint8_t>::iterator it) {
            for (unsigned i = 0; i < key.length(); ++i) {
                if (*it) return true; ++it;
            }        
            return false;
        }

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

bool isConfigSpecified(std::map<int,std::string> &fpqFiles) {
    return fpqFiles[FPQHeader::Type::Config].length() ? true : false;
}

bool isInputSpecified(std::map<int,std::string> &fpqFiles) {
    for (const auto &pair : fpqFiles) {
        if (pair.second.length() && pair.first != FPQHeader::Type::Config) return true;
    }
    return false;
}

bool isSerialValid(std::string serial) {
	if (serial.length() != std::string(DEFAULT_SERIAL).length()) return false;
	for (auto item : serial) {
		auto ch = std::tolower(item);
		if (ch < '0' || ch > '9') {
			if (ch < 'a' || ch > 'f') return false;
		}
	}
	return true;
}


int32_t main(int argc, char *argv[]) {

    PRINT_LONG_CAPTION;

    int opt;
    bool debug = false;
    FPQHeader header;
    FPQEncryptor encryptor;
    std::map<int,std::string> fpqFiles;
    std::map<int,std::string> fpqName = {
        {FPQHeader::Type::Config, "Config"},
		{FPQHeader::Type::Serial, "Serial"},
        {FPQHeader::Type::UBoot, "UBoot"},
        {FPQHeader::Type::Linux, "Linux"},
        {FPQHeader::Type::LiteOS, "Liteos"},
        {FPQHeader::Type::RootFS, "Rootfs"}
    };
    std::string outputPath = getCurrentDir() + std::string("/firmware.bin");
	uint32_t serialNumber = std::stoul(std::string(DEFAULT_SERIAL), 0, 16);

    if (sizeof(FPQHeader) != 512) {
        std::cout << "\n***Alignment test: ask = 512, take = ";
        std::cout << sizeof(FPQHeader) << "...Not passed! Exit!***\n" << std::endl;
        return -1;
    }

    while((opt = getopt(argc, argv, "c:b:x:s:f:o:k:d:")) != -1) {
        switch(opt) {
            case 'd': debug = true; break;
            case 'c': fpqFiles[FPQHeader::Type::Config] = std::string(optarg); break;
            case 'b': fpqFiles[FPQHeader::Type::UBoot] = std::string(optarg);  break;
            case 'x': fpqFiles[FPQHeader::Type::Linux] = std::string(optarg);  break;
            case 's': fpqFiles[FPQHeader::Type::LiteOS] = std::string(optarg); break;
            case 'f': fpqFiles[FPQHeader::Type::RootFS] = std::string(optarg); break;
            case 'o': outputPath = std::string(optarg); break;
            case 'k': 
                encryptor = std::string(optarg);
                if (!encryptor.isKeyValid()) {
                    std::cout << "Error! Encryption key length must be a power of two!" << std::endl;
                    return -1;
                }
            break;
			case 'h':
				if (!isSerialValid(std::string(optarg))) {
					std::cout << "Error! Invalid serial!" << std::endl;
                    return -1;
				}
				serialNumber = std::stoul(std::string(optarg), 0, 16);
			break;
            default: 
                printHelp(); return -1; 
            break;
        }
    }

    if (!isConfigSpecified(fpqFiles)) {
        printHelp();
        std::cout << "Error! Config file is not specified!" << std::endl;
        return -1;
    }

    if (!isInputSpecified(fpqFiles)) {
        printHelp();
        std::cout << "Error! No input files specified!" << std::endl;
        return -1;
    }

    if (debug) std::cout << "Output file: '" << outputPath << "'" << std::endl;
    FPQFile output(outputPath, FPQFile::OpenMode::RWCreate);
    if (!output.isOpened()) {
        std::cout << "Unable to open output file!" << std::endl;
    }
    output.seek(FPQHeader::blkSize());

    for (unsigned i = 0; i < FPQHeader::Type::FileNum_; ++i) {

		if (i == FPQHeader::Type::Serial) {
			std::vector<uint8_t> fileBlock(FPQHeader::blkSize(), 0);
			FPQHeader::makeSerial(serialNumber, fileBlock);

			if (debug) {
				std::cout << fpqName[i] << " size: " << FPQHeader::blkSize() << " bytes";
				std::cout << ", blk to read: " << FPQHeader::blkSize() / FPQHeader::blkSize() << std::endl;
			}

			encryptor.encrypt(fileBlock);

			if (!output.write(fileBlock.data(), fileBlock.size())) {
				std::cout << "Unable to write to '" << outputPath << "'!"<< std::endl;
				return -1;     
			}
			header.setSize((FPQHeader::Type)i, fileBlock.size());
		}
		else {
			FPQFile file(fpqFiles[i]);
			if (!file.isOpened()) {
				if (debug) std::cout << fpqName[i] << " skipping..." << std::endl;
				continue;
			}

			if (debug) {
				std::cout << fpqName[i] << " size: " << file.size() << " bytes";
				std::cout << ", blk to read: " << FPQHeader::align(file.size()) / FPQHeader::blkSize() << std::endl;
			}

			for (unsigned j = 0; j < FPQHeader::align(file.size()) / FPQHeader::blkSize(); ++j) {
				std::vector<uint8_t> fileBlock(FPQHeader::blkSize(), 0);

				if (!file.read(fileBlock.data(), std::min(file.size() - j * FPQHeader::blkSize(), FPQHeader::blkSize()))) {
					std::cout << "Unable to read from '" << fpqFiles[i] << "'!"<< std::endl;
					return -1;
				}

				encryptor.encrypt(fileBlock);

				if (!output.write(fileBlock.data(), fileBlock.size())) {
					std::cout << "Unable to write to '" << outputPath << "'!"<< std::endl;
					return -1;     
				}
			}
			header.setSize((FPQHeader::Type)i, file.size());
		}
    }

    header.updateOffsets();
    output.seek(0L);
    std::vector<uint8_t> fileBlock;
    fileBlock.resize(FPQHeader::blkSize());
    std::memcpy(fileBlock.data(), (uint8_t*)&header, fileBlock.size());
    encryptor.encrypt(fileBlock);
    if (!output.write(fileBlock.data(), fileBlock.size())) {
        std::cout << "Unable to write to '" << outputPath << "'!"<< std::endl;
        return -1;     
    }

    std::cout << "Done!" << std::endl; 
    return 0;
}
