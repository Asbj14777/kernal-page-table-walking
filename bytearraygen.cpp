#include <iostream>
#include <fstream>
#include <vector>

int main() {
    std::string filename;

    std::cout << "Enter the file path: ";
    std::getline(std::cin, filename);

    // Open the file in binary mode
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return 1;
    }

    // Get file size
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file content into a vector (byte array)
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Failed to read file data." << std::endl;
        return 1;
    }

    file.close();

    // Print the byte array in hex format
    std::cout << "Byte array of the file (" << size << " bytes):\n";
    for (size_t i = 0; i < buffer.size(); ++i) {
        printf("0x%02X", buffer[i]);
        if (i != buffer.size() - 1)
            std::cout << ", ";
        if ((i + 1) % 16 == 0)
            std::cout << "\n";
    }
    std::cout << std::endl;

    return 0;
}
