/* PCAPng Dolphin - a simple and fast TCP/UDP PCAPng Filter

Version 1.0

SPDX-License-Identifier: MIT

Copyright (C) 2020-2025 Martin Albert

NT-Dolphin and all it's derivation are released under the MIT license (see LICENSE.txt). Go to the project
home page for more info:

https://github.com/MACool8/NT_Dolphin
*/
#define VERSION "1.0"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include "ini.h"



#ifdef _WIN32
#define stat64 _stat64
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <tchar.h>
#define OS_PATH_SEPERATOR '\\'
#elif __linux__
#include <inttypes.h>
#include <unistd.h>
#define OS_PATH_SEPERATOR '/'
#define __int64 int64_t
#define _close close
#define _read read
#define _lseek64 lseek64
#define _O_RDONLY O_RDONLY
#define _open open
#define _lseeki64 lseek64
#define _lseek lseek
#define _stat64 stat
#define stricmp strcasecmp
#endif


#define ESC (char)0x1B
#define MAGIC_NUMBER_01 0xA1B2C3D4
#define MAGIC_NUMBER_02 0xA1B23C4D
#define BT_SECTION_HEADER 0x0A0D0D0A
#define BT_INTERFACE_DESCRIPTION 0x00000001
#define BT_ENH_PACKET_BLOCK 0x00000006
#define BYTE_ORDER_MAGIC 0x1A2B3C4D

#define WRITE_TO_FILE
#define CONFIG_FILE_NAME "config.ini"

#define true 1
#define false 0

// Maps a byte position in the file to its corresponding position in the ring buffer.
// This ensures correct access to the byte within the two-block circular buffer system.
// 
// Input:  Absolute byte position in the file.
// Output: Mapped byte position within the ring buffer
// Example usage: int int_in_file = *( (*int) (ring_buffer + BLOCK_POSITION(abs_pos_in_file_of_int)) ) 
#define BLOCK_POSITION(x) ((long long)(x)%(2*BLOCK_SIZE))


FILE* f_inp = 0;
FILE* f_out = 0;

const char* input_file;
const char* output_file;

// Defines the amount of bytes every Block will have
// Minimum: 4096, Maximum: BLOCK_SIZE * 2 < available RAM
unsigned long long BLOCK_SIZE = 16777216;//4096;


typedef struct
{
	int* TCP_Ports;
	unsigned int TCP_Ports_Count;

	int* UDP_Ports;
	unsigned int UDP_Ports_Count;
} Config;


Config config;

// Go throug pcap message, classify the content and return if filters passes or blocks the message
int Classify_Package(long long offset, unsigned char* buffer)
{
	int TCP_UDP = 0; // 0 = TCP, 1 = UDP
	int pos = 0;
	static int packet = 0;

	//////
	// PCAP Header
	//////

	// byte 8-12 are packet length 
	int packet_length = *(int*)(buffer + BLOCK_POSITION(offset + pos + 8));
	// 8 bytes for jumping over the timestamps and 8 for jumping over packet length and original packet length
	pos += 8 + 8;

	//////
	// Ethernet Header
	//////

	// The ethertype comes after the 12th byte in the ethernet packet
	// Ethertype are 2 bytes, but because of endinies, the bytes need to be swapped
	unsigned int Ethertype = (((*(unsigned int*)(buffer + BLOCK_POSITION(offset + pos + 12)) & 0xffff) << 8) + ((*(unsigned int*)(buffer + BLOCK_POSITION(offset + pos + 12)) & 0xffff) >> 8)) & 0xffff;

	// Drop all packackages that are not IPv4, IPv6 or VLAN
	if (!(Ethertype == 0x86DD || Ethertype == 0x8100 || Ethertype == 0x0800))
		return false;


	// Skip over MAC and go to IPv6, IPv4 or VLAN Package
	pos += 14;

	//////
	// VLAN Header
	//////

	// skip over VLAN if it's used
	if (Ethertype == 0x8100)
	{
		Ethertype = (((*(unsigned int*)(buffer + BLOCK_POSITION(offset + pos + 2)) & 0xffff) << 8) + ((*(unsigned int*)(buffer + BLOCK_POSITION(offset + pos + 2)) & 0xffff) >> 8)) & 0xffff;

		// Skip everything not IPv6
		if (Ethertype != 0x86DD)
			return false;

		pos += 4;

	}

	// From here 320 bits (40 bytes) should be for IPv6
	// or 160 bits (20 bytes) for IPv4

// Label only used for icmpv6
IP_dissection:

	//////
	// IPv4/IPv6 Header
	//////

	// Decide between IPv4 and IPv6
	int version = (*(int*)(buffer + BLOCK_POSITION(offset + pos)) & 0xf0) >> 4;
	// protocol (ipv4) or Next header (IPv6)
	unsigned char protocol;
	if (version == 4)
	{
		// IHL - Internet Header Length
		int header_length = (*(int*)(buffer + BLOCK_POSITION(offset + pos)) & 0x0f);
		protocol = *(unsigned char*)(buffer + BLOCK_POSITION(offset + pos + 9));
		pos += header_length*4;
	}
	else if (version == 6)
	{
		// protocol/next header is on the 6th byte of the IPv6 Frame
		protocol = *(unsigned char*)(buffer + BLOCK_POSITION(offset + pos + 6));
		// jumping over the IPv6 Header (assuming no Extensions)
		pos += 40;
	}
	else
		return false;

	// ICMPv6
	if (protocol == 58)
	{
		// only type 1 - 4 icmpv6 messages also come with the old message in it, so only those will be analyzed
		// ICMPv6-Type is always the first byte
		unsigned char ICMPv6_Type = *(unsigned char*)(buffer + BLOCK_POSITION(offset + pos));
		if (ICMPv6_Type >= 1 && ICMPv6_Type <= 4)
		{
			// Jump over all ICMPv6 bytes (8 bytes)
			pos += 8;
			// inside the ICMPv6 Message is the IPv6 Message which lead to this ICMPv6 message
			goto IP_dissection;
		}
		// every other ICMPv6-Type will be discarded
		else
			return false;
	}
	// ICMP for IPv4 
	else if (protocol == 1)
	{
		// ICMP that have the head of the original massage in their data section
		// (3) Destination Unreachable Message
		// (4) Source Quench Message
		// (5) Redirect Message
		// (11) Time Exceeded Message 
		// (12) Parameter Problem Message 
		int ICMP_types_with_data[5] = { 3,4,5,11,12 };
		int ICMP_type = *(int*)(buffer + BLOCK_POSITION(offset + pos)) & 0xff;

		// Check if ICMP type is one that should have data and restart the decoding from there
		for (int i = 0; i < 5; i++)
		{
			if (ICMP_type == ICMP_types_with_data[i])
			{
				pos += 8;
				goto IP_dissection;
			}
		}
		return false;
	}

	//////
	// TCP/UDP Header
	//////

	//TCP Port searching
	if (protocol == 6)
	{
		unsigned int Ports = *(int*)(buffer + BLOCK_POSITION(offset + pos));
		unsigned int sPort = (Ports >> 24) + ((Ports & 0x00ff0000) >> 8);
		unsigned int dPort = ((Ports & 0x000000ff) << 8) + ((Ports & 0x0000ff00) >> 8);

		for (int i = 0; i < config.TCP_Ports_Count; i++)
		{
			if (config.TCP_Ports[i] == sPort)
			{
				//sPort and Port Matched
				return true;
			}
			else if (config.TCP_Ports[i] == dPort)
			{
				//dPort and Port Matched
				return true;
			}
		}


	}
	//UDP Port searching
	else if(protocol == 17)
	{
		unsigned int Ports = *(int*)(buffer + BLOCK_POSITION(offset + pos));
		unsigned int sPort = (Ports >> 24) + ((Ports & 0x00ff0000) >> 8);
		unsigned int dPort = ((Ports & 0x000000ff) << 8) + ((Ports & 0x0000ff00) >> 8);

		for (int i = 0; i < config.UDP_Ports_Count; i++)
		{
			if (config.UDP_Ports[i] == sPort)
			{
				//sPort and Port Matched
				return true;
			}
			else if (config.UDP_Ports[i] == dPort)
			{
				//dPort and Port Matched
				return true;
			}
		}
	}

	// If no ports matched
	return false;
}

void Close_all()
{
	if (f_inp != 0)
	{
		fclose(f_inp);
		f_inp = 0;
	}
#ifdef WRITE_TO_FILE
	if (f_out != 0)
	{
		fclose(f_out);
		f_out = 0;
	}
#endif
}

void Open_all()
{
#ifdef _WIN32
	fopen_s(&f_inp, input_file, "rb");
#elif __linux__
	f_inp = fopen(input_file, "rb");
#endif


	if (f_inp == 0)
	{
		printf("Didn't open input file, bailing out!\n");
#ifdef _WIN32
		system("pause");
#endif
		exit(2);
	}

	//fopen_s(&f_index, index_file, "wb");
	/*if (f_index == 0)
	{
		printf("Didn't open index file, bailing out!\n");
		exit(2);
	}*/

#ifdef WRITE_TO_FILE

#ifdef _WIN32
	fopen_s(&f_out, output_file, "wb");
#elif __linux__
	f_out = fopen(output_file, "wb");
#endif

	if (f_out == 0)
	{
		printf("Couldn't open output file, bailing out!\n");
		Close_all();
#ifdef _WIN32
		system("pause");
#endif
		exit(2);
	}
#endif
}

void Add_Suffix(const char* input, const char* Addon, char* output, int output_buffersize) 
{
	char* dot = strrchr(input, '.');
	if (dot)
		snprintf(output, output_buffersize, "%.*s%s%s", (int)(dot - input), input, Addon, dot);
	else
		snprintf(output, output_buffersize, "%s%s", input, Addon);
}

// Take input filename and generate a filename within this folder with addon
const char* Initialize_Output_File(const char* input_file)
{
	int input_length = strlen(input_file);
	const char* Addon = "_filtered";
	int Addon_length = strlen(Addon);
	// Check filetype
	if (!(strcmp(input_file + input_length - 7, ".pcapng") == 0 || strcmp(input_file + input_length - 7, ".PCAPNG") == 0))
	{
		printf("File not a .pcapng file. Bailing out! \n Filename: %s\n", input_file);
#ifdef _WIN32
		system("pause");
#endif
		exit(1);
	}
	/*
	char* output_dir = (char*)malloc(sizeof(char) * (input_length + 1));
#ifdef _WIN32
	strcpy_s(output_dir, input_length + 1, input_file);
#elif __linux__
	strncpy(output_dir, input_file, input_length + 1);
#endif
	// cut of the .pcap
	output_dir[input_length - 7] = '\0';

	
	// Either check if folder already exists or create the folder
	struct stat sb;
#ifdef _WIN32	
	if (!(stat(output_dir, &sb) == 0 && (S_IFDIR & sb.st_mode) != 0) && _mkdir(output_dir) == -1)
	{
		printf("Can't create output folder. Bailing out. \n Tried to create: %s\n", output_dir);
		system("pause");
		exit(1);
	}
#elif __linux__
	if (!(stat(output_dir, &sb) == 0 && S_ISDIR(sb.st_mode)) && mkdir(output_dir, 0770) == -1)
	{
		printf("Can't create output folder. Bailing out. \n Tried to create: %s\n", output_dir);
		exit(1);
	}
#endif

	// strrchr gives a pointer to the last occerence of a char in a string


	char* output_dir_name_only = strrchr(output_dir, OS_PATH_SEPERATOR);
	if (output_dir_name_only == 0)
		output_dir_name_only = output_dir;
	else
		// remove leading '\'
		output_dir_name_only += 1;

	int output_dir_length = strlen(output_dir_name_only);
	*/

	int output_size = input_length + Addon_length + 2;
	// + 2 bytes for the \ of the output_dir and \0 of the string
	char* output = (char*)malloc(sizeof(char) * output_size);

	Add_Suffix(input_file, Addon, output, output_size);

	//free(output_dir);

	//remove the ng from pcapng
	int len = strlen(output);
	output[len - 2] = '\0';


	return output;
}

void LoadInBlock(unsigned char* buffer, long long RequestedBlockNumber, long long size_of_file)
{
	int block_position = (RequestedBlockNumber % 2) * BLOCK_SIZE;

	unsigned long long Read_Size = BLOCK_SIZE;
	if (RequestedBlockNumber * BLOCK_SIZE + BLOCK_SIZE > size_of_file)
	{
		Read_Size = size_of_file - (RequestedBlockNumber * BLOCK_SIZE);
	}

	unsigned long long out = fread(buffer + block_position, 1, Read_Size, f_inp);

	if (out != Read_Size)
	{
		printf("Couldn't read the %lld block fully, bailing out! Error Code: %d, EOF: %b\n", RequestedBlockNumber, ferror(f_inp), feof(f_inp));
		Close_all();
#ifdef _WIN32
		system("pause");
#endif
		exit(4);
	}

	// To understand see the "Non-Alignment"-Topic above 
	if (!(RequestedBlockNumber % 2))
	{
		buffer[2 * BLOCK_SIZE] = buffer[0];
		buffer[2 * BLOCK_SIZE + 1] = buffer[1];
		buffer[2 * BLOCK_SIZE + 2] = buffer[2];
	}
}

#ifdef _WIN32

void EnableANSIEscapeCharsinWindows()
{
	// Set output mode to handle virtual terminal sequences
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut == INVALID_HANDLE_VALUE)
	{
		exit(GetLastError());
	}

	DWORD dwMode = 0;
	if (!GetConsoleMode(hOut, &dwMode))
	{
		exit(GetLastError());
	}

	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	if (!SetConsoleMode(hOut, dwMode))
	{
		exit(GetLastError());
	}
}

#endif

// Takes a string with \0 ending and creates an array out of comma seperated numbers in the string
void StrToIntArray(const char* input, unsigned int** output_array, unsigned int* output_count)
{
	int count_of_ints = 0;
	int pos = 0;
	int found_nr = false;
	// Counting how many ints there will be
	while (input[pos] != '\0')
	{

		if (input[pos] > 47 && input[pos] < 58)
			found_nr = true;

		else if (input[pos] == '#' || input[pos] == '\n' || input[pos] == '\0')
			break;

		else if (input[pos] == ',' && found_nr)
		{
			count_of_ints++;
			found_nr = false;
		}

		pos++;
	}
	if (found_nr)
	{
		count_of_ints++;
		found_nr = false;
	}

	unsigned int* temp = (unsigned int*)malloc(sizeof(int) * count_of_ints);

	pos = 0;
	unsigned int current_number = MAXUINT32;
	unsigned int current_array_pos = 0;
	unsigned int invalid_space_detected = false;
	while (1)
	{
		if (input[pos] == ' ')
		{
			if (current_number != MAXUINT32)
			{
				// Error of wrongly used space only gets triggered if any numerical chars come after that
				invalid_space_detected = true;
			}
		}
		else if (input[pos] > 47 && input[pos] < 58)
		{
			if (invalid_space_detected)
			{
				printf("Invalid space used in '%s'. Did you forget a comma? Bailing out!", input);
				exit(1);
			}

			if (current_number == MAXUINT32)
				current_number = 0;

			current_number = current_number * 10 + input[pos] - 48;
		}
		else if (input[pos] == ',')
		{
			temp[current_array_pos] = current_number;
			current_array_pos++;
			current_number = MAXUINT32;
			invalid_space_detected = false;
		}
		// Exit condition with 
		else if (input[pos] == '\0')
		{
			temp[current_array_pos] = current_number;
			break;
		}
		else
		{
			printf("Found unexpected char '%c' (%x) in int array. Bailing out!", input[pos] & 0xff, input[pos] & 0xff);
			exit(1);
		}
		pos++;

	}

	*output_array = temp;

	*output_count = count_of_ints;
}

// Handler for the INIH Library (for each entry in the ini file this handler gets called)
static int ini_entry_handler(void* conf, const char* section, const char* name, const char* value)
{
	Config* pconfig = (Config*)conf;

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)
	if (MATCH("Filter", "UDP"))
	{
		StrToIntArray(value, &(pconfig->UDP_Ports), &(pconfig->UDP_Ports_Count));
	}
	else if (MATCH("Filter", "TCP"))
	{
		StrToIntArray(value, &(pconfig->TCP_Ports), &(pconfig->TCP_Ports_Count));
	}
	else
	{
		return 0;  /* unknown section/name, error */
	}
	return 1;
}

void LoadInConfigFile()
{

	// Get location of the config file, located in the same directory as the executable.
#ifdef _WIN32
	TCHAR Absolut_Config_File_Path[MAX_PATH];
	int Full_path_len = GetModuleFileName(NULL, Absolut_Config_File_Path, MAX_PATH);
	TCHAR* Start_Of_executable_Name = _tcsrchr(Absolut_Config_File_Path, _T('\\')) + 1;
	// Shorten string to only folder by setting null char after the last '\'
	*Start_Of_executable_Name = Absolut_Config_File_Path[Full_path_len];
	lstrcpy(Start_Of_executable_Name, _T("config.ini\0"));
	FILE* file;
	_tfopen_s(&file, Absolut_Config_File_Path, _T("r"));
#elif __linux__
	const char Absolut_Config_File_Path[4096];
	ssize_t readsize = readlink("/proc/self/exe", Absolut_Config_File_Path, 4096);
	Absolut_Config_File_Path[readsize] = '\0';
	dirname(Absolut_Config_File_Path);
	strcat(Absolut_Config_File_Path, "/");
	strcat(Absolut_Config_File_Path, CONFIG_FILE_NAME);
	FILE* file = fopen_s(Absolut_Config_File_Path, "r");
#endif

	if (file == 0)
	{
		printf("Couldn't open config file '%s'. Bailing Out!\n", Absolut_Config_File_Path);
#ifdef _WIN32
		system("pause");
#endif
		exit(1);
	}

	memset(&config, 0, sizeof(Config));

	if (ini_parse_file(file, ini_entry_handler, &config) < 0) {
		printf("Error while loading interpreting the Config file. Bailing out!\n");
#ifdef _WIN32
		system("pause");
#endif
		exit(1);
	}

}

int main(int argc, char* argv[])
{
	// Catching User Errors
	if (argc != 2 || argv[1][0] == '-')
	{
		printf("Version: %s\nUsage: %s <pcap_file>\n", VERSION, argv[0]);
		exit(1);
	}

#ifdef _WIN32
	EnableANSIEscapeCharsinWindows();
#endif

	printf("Reading in config: %s\n", CONFIG_FILE_NAME);

	LoadInConfigFile();

	printf("Following configurations have been read in:\nTCP: ");
	for (int i = 0; i < config.TCP_Ports_Count; i++)
	{
		printf("%d, ", config.TCP_Ports[i]);
	}
	printf("\nUDP: ");
	for (int i = 0; i < config.UDP_Ports_Count; i++)
	{
		printf("%d, ", config.UDP_Ports[i]);
	}

	printf("Reading in PCAPng File: %s\n", argv[1]);

	input_file = argv[1];
	output_file = Initialize_Output_File(input_file);

	printf("Storing output in: %s\n", output_file);

	// Prevent overwriting in error cases
	if (strcmp(input_file, output_file) == 0)
	{
		printf("Internal Error lead to input and output file to be the same. Won't overwrite input file. Bailing out!\n");
#ifdef _WIN32
		system("pause");
#endif
		exit(1);
	}

#ifdef _WIN32
	clock_t spent_loading_in = 0;
	clock_t spent_calculating = 0;
	clock_t spent_saving = 0;
#endif

	clock_t begin = clock();
	long long pos = 0;
	long long current_block = 0;

	printf("Reading in messages...\n");

	struct _stat64 stats;
	_stat64(input_file, &stats);
	long long size_of_file = stats.st_size;

	Open_all();

	unsigned char* buffer = (unsigned char*)malloc(sizeof(char) * BLOCK_SIZE * 2 + sizeof(char) * 3);

	if (buffer == 0)
	{
		printf("Didn't get memory for Ring-Buffer, bailing out!\n");
		Close_all();
		return 3;
	}

#ifdef _WIN32
	clock_t s_load = clock();
#endif

	LoadInBlock(buffer, 0, size_of_file);

#ifdef _WIN32
	clock_t e_load = clock();
	spent_loading_in += e_load - s_load;
#endif

	// Sanity Check if Files is a PCAPNG file and in the endiness of the current file system
	unsigned int First_Block_Type = *((unsigned int*)buffer);
	unsigned int Byte_Order_MAGIC = *((unsigned int*)(buffer + 8));
	if (!(First_Block_Type == BT_SECTION_HEADER || Byte_Order_MAGIC == BYTE_ORDER_MAGIC))
	{
		if (!First_Block_Type == BT_SECTION_HEADER)
		{
			printf("First_Block_Type not correct. Normal:%x Is:%x \n bailing out!\n", BT_SECTION_HEADER, First_Block_Type);
		}
		else
		{
			printf("Byte_Order_MAGIC not correct. Normal:%x Is:%x \n bailing out!\n", BYTE_ORDER_MAGIC, Byte_Order_MAGIC);
		}
		return 1;
	}

	pos = 0;

	long long offset = 0;
	int* Good_Interfaces = 0;
	unsigned int Good_Interfaces_Size = 0;
	unsigned int Interface_Count = 0;
	long long counter = 0;
	long long tls_counter = 0;
	int percentage = 0;
	int last_percentage = 0;
	unsigned long long current_second_scale = 1000000;

#ifdef WRITE_TO_FILE
	//Write Header of pcap file
	unsigned char PCAP_HEADER[] = { 0xD4,0xC3,0xB2,0xA1,0x02,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,0x01,0x00,0x00,0x00 };
	fwrite(PCAP_HEADER, 1, 24, f_out);
#endif

	printf("Filtering:\x1B[32m %02d %%%c%s", percentage, ESC, "[2D");
	fflush(stdout);
	while (pos + 1 < size_of_file)
	{
		if ((current_block + 1) * BLOCK_SIZE < (long long)(pos + 8))
		{
#ifdef _WIN32
			s_load = clock();
#endif
			LoadInBlock(buffer, ++current_block, size_of_file);
#ifdef _WIN32
			e_load = clock();
			spent_loading_in += e_load - s_load;
#endif
		}

		unsigned int packet_length = *((unsigned int*)(buffer + BLOCK_POSITION(pos + 4)));

		if ((current_block + 1) * BLOCK_SIZE < (long long)(pos + packet_length))
		{
#ifdef _WIN32
			s_load = clock();
#endif
			LoadInBlock(buffer, ++current_block, size_of_file);
#ifdef _WIN32
			e_load = clock();
			spent_loading_in += e_load - s_load;
#endif
		}
		unsigned int Block_Type = *((unsigned int*)(buffer + BLOCK_POSITION(pos)));
		if (Block_Type == BT_SECTION_HEADER)
		{
			unsigned int Byte_Order_MAGIC = *((unsigned int*)(buffer + BLOCK_POSITION(pos + 8)));
			if (!(Byte_Order_MAGIC == BYTE_ORDER_MAGIC))
			{
				printf("New section doesn't has the right Byte Order. Bailing out!\n");
#ifdef _WIN32
				system("pause");
#endif
				exit(1);
			}

			// Reset List of good interfaces
			if (!Good_Interfaces == 0)
			{
				free(Good_Interfaces);
				Good_Interfaces = 0;
				Good_Interfaces_Size = 0;
				Interface_Count = 0;
			}

			pos += packet_length;
		}
		else if (Block_Type == BT_INTERFACE_DESCRIPTION)
		{
			unsigned short LinkType = *((unsigned short*)(buffer + BLOCK_POSITION(pos + 8)));
			// If LinkType is ethernet, mark as usable interface
			if (LinkType == 0x1)
			{
				int* temp = (int*)malloc((sizeof(int) * (Good_Interfaces_Size + 1)));
				if (Good_Interfaces != 0)
				{
					memcpy(temp, Good_Interfaces, sizeof(int) * Good_Interfaces_Size);
					free(Good_Interfaces);
				}
				temp[Good_Interfaces_Size] = Interface_Count;
				Good_Interfaces_Size++;
				Good_Interfaces = temp;


				// update time scale if available
				unsigned int cur = 0;
				while (20 + cur < packet_length)
				{
					unsigned short option_code = *((unsigned short*)(buffer + BLOCK_POSITION(pos + 16 + cur)));
					unsigned short option_length = *((unsigned short*)(buffer + BLOCK_POSITION(pos + 18 + cur)));

					// to-do: check for options ... look up if_tsresol ...
					if (option_code == 9)
					{
						current_second_scale = 1000000;
						unsigned char timescale_byte = *((unsigned char*)(buffer + BLOCK_POSITION(pos + 20 + cur)));

						if (timescale_byte & 0x80)
						{
							current_second_scale = ((unsigned long long)0x1 << (timescale_byte & 0x7f));
						}
						else
						{
							current_second_scale = (unsigned long long)0x1;
							for (int i = 0; i < timescale_byte; i++)
								current_second_scale *= 10;
						}
					}
					// skip option header + option value
					cur += 4;
					cur += option_length;
					// skip padding bytes
					cur += (4 - cur) % 4;
				}
			}
			Interface_Count++;
			pos += packet_length;
		}
		else if (Block_Type == BT_ENH_PACKET_BLOCK)
		{


#ifdef _WIN32
			s_load = clock();
#endif
			// check if interface is ethernet
			unsigned int Matched_Interface = false;
			for (int i = 0; i < Good_Interfaces_Size; i++)
			{
				unsigned int InterfaceID = *((unsigned int*)(buffer + BLOCK_POSITION(pos + 8)));
				if (InterfaceID == Good_Interfaces[i])
				{
					Matched_Interface = true;
					break;
				}

				// if not matching any interface, skip message
				if (i == Good_Interfaces_Size - 1)
				{
					Matched_Interface = false;
				}
			}

			if (!Matched_Interface)
			{
				pos += packet_length;
				continue;
			}

			// By skipping Block Type(4bytes), Length(4bytes) and InterfaceID(4bytes)
			// the rest can be read like an original pcap-packet (except the timestamp and additional data after the packet data)
			int filters_matched = Classify_Package(pos + 12, buffer);

#ifdef _WIN32
			e_load = clock();
			spent_calculating += e_load - s_load;
#endif
			if (filters_matched)
			{
				tls_counter += 1;
#ifdef WRITE_TO_FILE

#ifdef _WIN32
				s_load = clock();
#endif
				// pcapng uses 64 bit timestamps for seconds and pcaps use 32 bit timestamps with 32 bit for nanoseconds
				unsigned int temp = *((unsigned int*)(buffer + BLOCK_POSITION(pos + 12)));
				*((unsigned int*)(buffer + BLOCK_POSITION(pos + 12))) = *((unsigned int*)(buffer + BLOCK_POSITION(pos + 16)));
				*((unsigned int*)(buffer + BLOCK_POSITION(pos + 16))) = temp;
				unsigned long long timestamp = *((unsigned long long*)(buffer + BLOCK_POSITION(pos + 12)));
				*((unsigned int*)(buffer + BLOCK_POSITION(pos + 12))) = timestamp / current_second_scale;
				*((unsigned int*)(buffer + BLOCK_POSITION(pos + 16))) = (timestamp % current_second_scale) / 1000;

				unsigned int pcap_packet_length = *((unsigned int*)(buffer + BLOCK_POSITION(pos + 20)));

				offset = pos + 12;

				// If the message is seperated into two blocks, the fwrite function needs to be done for each block sepperatly as the data is not laying in memory continously
				if (BLOCK_POSITION(offset) > BLOCK_POSITION(offset + pcap_packet_length + 16))
				{
					int Bytes_in_second_block = 2 * BLOCK_SIZE - BLOCK_POSITION(offset);
					fwrite((void*)(buffer + BLOCK_POSITION(offset)), 1, Bytes_in_second_block, f_out);
					fwrite(buffer, 1, 16 + pcap_packet_length - Bytes_in_second_block, f_out);
				}
				else
					fwrite(buffer + BLOCK_POSITION(offset), 1, 16 + pcap_packet_length, f_out);

#ifdef _WIN32
				e_load = clock();
				spent_saving += e_load - s_load;
#endif
#endif // Write to file endif


			}
			pos += packet_length;
		}
		// Skip all other Block Types
		else
		{
			pos += packet_length;
		}
		counter++;
		percentage = (pos * 100) / size_of_file;

		// only print an update to the percentage if there is one
		if (last_percentage != percentage)
		{
			// Special move, which goes two chars back and overwrites those two chars with the new percentage
			printf("%c%s%02d", ESC, "[2D", percentage);
			last_percentage = percentage;
			fflush(stdout);
		}

	}

	Close_all();

	clock_t end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

#ifdef _WIN32
	double time_spent_loading = (double)spent_loading_in / CLOCKS_PER_SEC;
	double time_spent_calculating = (double)spent_calculating / CLOCKS_PER_SEC;
	double time_spent_saving = (double)spent_saving / CLOCKS_PER_SEC;
#endif

	printf(" %%\033[0m\nDone! Total Time: \x1B[31m %lf \033[0m seconds!\n", time_spent);

#ifdef _WIN32	
	// The timecalculations are only efficiant in Windows (somehow clock() takes a lot of time in loops in linux), therefore linux users won't have more in depth performance data 
	printf("Out of the \x1B[31m %lf \033[0m seconds, \x1B[36m %lf \033[0m seconds were spent on loading in the file and \x1B[32m %lf \033[0m seconds were spent on analyzing the packets. It also took \x1B[33m %lf \033[0m seconds to save the output.\n", time_spent, time_spent_loading, time_spent_calculating, time_spent_saving);
#endif

	free(buffer);
	free((void*)output_file);

#ifdef _WIN32
	system("pause");
#endif

	return 0;
}


/*
PCAP Format: https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html
PCAPng Format: https://pcapng.com/

TCP Frame: https://en.wikipedia.org/wiki/Transmission_Control_Protocol
ICMPv6 Frame:https://en.wikipedia.org/wiki/ICMPv6
ICMP (IPv4) Frame: https://datatracker.ietf.org/doc/html/rfc792 https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
IPv6 Frames: https://en.wikipedia.org/wiki/IPv6#IPv6_packets
IPv4 Frames: https://en.wikipedia.org/wiki/IPv4#Packet_structure
Ethertypes: https://en.wikipedia.org/wiki/EtherType#Values

lseek: https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/lseek-lseeki64?view=msvc-170
Thrust for cuda bitmap indexing: https://code.google.com/archive/p/thrust/   https://github.com/NVIDIA/thrust
YAF: https://tools.netsa.cert.org/yaf/yaf_pcap.html
PcapWT: https://www.researchgate.net/publication/270595918_PcapWT_An_Efficient_Packet_Extraction_Tool_for_Large_Volume_Network_Traces


*/