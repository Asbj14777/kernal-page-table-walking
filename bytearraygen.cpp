#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

int main(int argc, char* argv[]) {
    std::string inputFile;
    std::string outputFile;
    if (argc > 1) {
        inputFile = argv[1];
        std::cout << "File detected: " << inputFile << std::endl;
    } else {
        std::cout << "Enter the path of the file to embed: ";
        std::getline(std::cin, inputFile);
    }
    size_t lastSlash = inputFile.find_last_of("\\/");
    std::string fileNameOnly = (lastSlash != std::string::npos) ? inputFile.substr(lastSlash + 1) : inputFile;
    outputFile = fileNameOnly + ".h"; 
    std::ifstream file(inputFile, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << inputFile << std::endl;
        return 1;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Failed to read file data." << std::endl;
        return 1;
    }
    file.close();
    std::ofstream out(outputFile);
    if (!out.is_open()) {
        std::cerr << "Failed to open output file: " << outputFile << std::endl;
        return 1;
    }
    out << "unsigned char g_EmbeddedDll[] = {\n";
    for (size_t i = 0; i < buffer.size(); ++i) {
        out << "0x" << std::hex << std::uppercase 
            << std::setw(2) << std::setfill('0') 
            << static_cast<int>(buffer[i]);
        if (i != buffer.size() - 1)
            out << ", ";
        if ((i + 1) % 16 == 0)
            out << "\n";
    }
    out << "\n};\n";
    out.close();
    std::cout << "Byte array successfully written to " << outputFile << std::endl;
    return 0;
}
