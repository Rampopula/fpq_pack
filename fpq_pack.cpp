#include <cstdint>
#include <iostream>
#include <memory>
#include <fstream>
#include <getopt.h>
#include <unistd.h>

#define FIRMWARE_HEADER				"~magic~firmware~"
#define FIRMWARE_BLOCK_SIZE			(512)			
#define FIRMWARE_ALIGN(x)			(((x)%512)?((x)+(512-((x)%512))):(x))


void help() {
    std::cout << "*** FPQ Pack ***" << std::endl;
	std::cout << "Usage: fpq_pack -b /uboot -x /linux -s /liteos -f /rootfs -o /out -d" << std::endl;
	std::cout << "\n\t[-d] - debug mode" << std::endl;
    std::cout << "\t[-b path] - uboot path" << std::endl;
    std::cout << "\t[-x path] - linux path" << std::endl;
    std::cout << "\t[-s path] - liteos path" << std::endl;
    std::cout << "\t[-f path] - rootfs path" << std::endl;
	std::cout << "\t[-o path] - output path" << std::endl;
	std::cout << "\nNote[1]: You can only specify the parameters that you need, but at least one." << std::endl;
	std::cout << "Note[2]: If '-o' is not specified, then output file will be created in current directory." << std::endl;
    std::cout << std::endl;
}


class FirmwareFile {
	public:
		enum class OpenMode {rw_open, rw_creat};

		explicit FirmwareFile(std::string path, FirmwareFile::OpenMode mode) : file(NULL) {
			FILE *file = NULL;
			std::string openMode = (mode == FirmwareFile::OpenMode::rw_creat) ? std::string("w+b") : std::string("r+b");
			file = fopen(path.c_str(), openMode.c_str());
			if (file) this->file = file;
		}
		explicit FirmwareFile(std::string path) : FirmwareFile(path, FirmwareFile::OpenMode::rw_open) {}
		~FirmwareFile() { if (file) fclose(file); }

		bool isOpened(void) const {
			return file ? true : false;
		}

		unsigned size() const {
			unsigned fileSize;
			if (!isOpened()) return 0;
			fseek(file, 0L, SEEK_END);
			fileSize = ftell(file);
			fseek(file, 0L, SEEK_SET);
			return fileSize;
		}

		unsigned read(uint8_t *data, unsigned size) { 
			if (!isOpened() || !data) return 0;
			return fread(data, sizeof(uint8_t), size, file);
		}

		unsigned write(uint8_t *data, unsigned size) {
			if (!isOpened() || !data) return 0;
			return fwrite(data, sizeof(uint8_t), size, file);
		}

		unsigned write(uint8_t *data, unsigned size, long offset) {
			if (!isOpened() || !data) return 0;
			fseek(file, offset, SEEK_SET);
			return fwrite(data, sizeof(uint8_t), size, file);
		}
	private:
		FILE *file;
};


enum  Firmware { UBoot = 0, Linux, LiteOS, RootFS, Count_ };

struct FirmwareHeader {
	const char firmware_magic[16] = {'~','m','a','g','i','c','~','f','i','r','m','w','a','r','e','~',};
	uint32_t uboot_size;
	uint32_t uboot_offset;
	uint32_t linux_size;
	uint32_t linux_offset;
	uint32_t liteos_size;
	uint32_t liteos_offset;
	uint32_t rootfs_size;
	uint32_t rootfs_offset;
	uint8_t alignment[464];
};


int32_t main(int argc, char *argv[]) {

	int opt;
	bool debug = false;
	unsigned fileSize;
	bool inputSpecified = false;
	std::unique_ptr<uint8_t[]> fileBuffer[Count_];
	auto currentDir = std::unique_ptr<char,decltype(&free)>(get_current_dir_name(), free);
	std::string outputPath(currentDir.get() + std::string("/firmware.bin"));
	std::string firmwarePath[Count_];
	FirmwareHeader firmwareHeader;

	while((opt = getopt(argc, argv, "db:x:s:f:o:")) != -1) {
		switch(opt) {
			case 'b': 
				firmwarePath[UBoot] = std::string(optarg);
				inputSpecified = true;
			break;
			case 'x': 
				firmwarePath[Linux] = std::string(optarg);
				inputSpecified = true;
			break;
			case 's': 
				firmwarePath[LiteOS] = std::string(optarg);
				inputSpecified = true;
			break;
			case 'f': 
				firmwarePath[RootFS] = std::string(optarg);
				inputSpecified = true;
			break;
			case 'o': 
				firmwarePath[UBoot] = std::string(optarg); 
			break;
			case 'd':
				debug = true; 
			break;
			default: 
				help();
				return -1;
			break;
		}
	}
	if (!inputSpecified) {
		help();
		std::cout << "No input files specified!" << std::endl;
		return -1;
	}
	
	{	
		// Open UBoot
		fileSize = 0;
		FirmwareFile ubootFile(firmwarePath[UBoot].c_str());
		if (ubootFile.isOpened()) {
			fileSize = ubootFile.size();
			if (debug) std::cout << "uboot size: 0x" << std::hex << fileSize << " b" << std::endl;
			fileBuffer[UBoot] = std::unique_ptr<uint8_t[]>(new uint8_t[FIRMWARE_ALIGN(fileSize)]);
			if (ubootFile.read(fileBuffer[UBoot].get(), fileSize) != fileSize) {
				std::cout << "Unable to read uboot file!" << std::endl;
				return -1;
			}
		} 
		else if (debug) std::cout << "skipping uboot..." << std::endl; 

		// Set UBoot offset & size
		firmwareHeader.uboot_size = FIRMWARE_ALIGN(fileSize);
		firmwareHeader.uboot_offset = FIRMWARE_BLOCK_SIZE;
	}

	{
		// Open Linux
		fileSize = 0;
		FirmwareFile linuxFile(firmwarePath[Linux].c_str());
		if (linuxFile.isOpened()) {
			fileSize = linuxFile.size();
			if (debug) std::cout << "linux size: 0x" << fileSize << " b" << std::endl;
			fileBuffer[Linux] = std::unique_ptr<uint8_t[]>(new uint8_t[FIRMWARE_ALIGN(fileSize)]);
			if (linuxFile.read(fileBuffer[Linux].get(), fileSize) != fileSize) {
				std::cout << "Unable to read linux file!" << std::endl;
				return -1;
			}
		} 
		else if (debug) std::cout << "skipping linux..." << std::endl;

		// Set Linux offset & size
		firmwareHeader.linux_size = FIRMWARE_ALIGN(fileSize);
		firmwareHeader.linux_offset = firmwareHeader.uboot_offset + firmwareHeader.uboot_size;
	}

	{
		// Open LiteOS
		fileSize = 0;
		FirmwareFile liteosFile(firmwarePath[LiteOS].c_str());
		if (liteosFile.isOpened()) { 
			fileSize = liteosFile.size();
			if (debug) std::cout << "liteos size: 0x" << fileSize << " b" << std::endl;
			fileBuffer[LiteOS] = std::unique_ptr<uint8_t[]>(new uint8_t[FIRMWARE_ALIGN(fileSize)]);
			if (liteosFile.read(fileBuffer[LiteOS].get(), fileSize) != fileSize) {
				std::cout << "Unable to read liteos file!" << std::endl;
				return -1;
			}
		}
		else if (debug) std::cout << "skipping liteos..." << std::endl;

		// Set LiteOS offset & size
		firmwareHeader.liteos_size = FIRMWARE_ALIGN(fileSize);
		firmwareHeader.liteos_offset = firmwareHeader.linux_offset + firmwareHeader.linux_size;
	}

	{
		// Open RootFS
		fileSize = 0;
		FirmwareFile rootfsFile(firmwarePath[RootFS].c_str());
		if (rootfsFile.isOpened()) {
			fileSize = rootfsFile.size();
			if (debug) std::cout << "rootfs size: 0x" << fileSize << " b" << std::endl;
			fileBuffer[RootFS] = std::unique_ptr<uint8_t[]>(new uint8_t[FIRMWARE_ALIGN(fileSize)]);
			if (rootfsFile.read(fileBuffer[RootFS].get(), fileSize) != fileSize) {
				std::cout << "Unable to read rootfs!" << std::endl;
				return -1;
			}
		}
		else if (debug) std::cout << "skipping rootfs..." << std::endl;

		// Set RootFS offset & size
		firmwareHeader.rootfs_size = FIRMWARE_ALIGN(fileSize);
		firmwareHeader.rootfs_offset = firmwareHeader.liteos_offset + firmwareHeader.liteos_size;
	}

	{
		// Write output file
		FirmwareFile outputFile(outputPath.c_str(), FirmwareFile::OpenMode::rw_creat);
		if (!outputFile.isOpened()) {
			std::cout << "Unable to create output file!" << std::endl;
			return -1;
		}

		// Write header
		outputFile.write((uint8_t*)&firmwareHeader, sizeof(FirmwareHeader));

		// Write UBoot
		if (fileBuffer[UBoot].get()) {
			if (debug) std::cout << "uboot offset: 0x" << firmwareHeader.uboot_offset << std::endl;
			outputFile.write(fileBuffer[UBoot].get(), firmwareHeader.uboot_size, firmwareHeader.uboot_offset);
		}
		

		// Write Linux
		if (fileBuffer[Linux].get()) {
			if (debug) std::cout << "linux offset: 0x" << firmwareHeader.linux_offset << std::endl;
			outputFile.write(fileBuffer[Linux].get(), firmwareHeader.linux_size, firmwareHeader.linux_offset);
		}
		

		// Write LiteOS
		if (fileBuffer[LiteOS].get()) {
			if (debug) std::cout << "liteos offset: 0x" << firmwareHeader.liteos_offset << std::endl;
			outputFile.write(fileBuffer[LiteOS].get(), firmwareHeader.liteos_size, firmwareHeader.liteos_offset);
		}

		// Write RootFS
		if (fileBuffer[RootFS].get()) {
			if (debug) std::cout << "rootfs offset: 0x" << firmwareHeader.rootfs_offset << std::endl;
			outputFile.write(fileBuffer[RootFS].get(), firmwareHeader.rootfs_size, firmwareHeader.rootfs_offset);
		}
	}

	std::cout << "Done!" << std::endl;
    return 0;
}
