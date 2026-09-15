#ifndef WITNESS_UTILITIES_HPP
#define WITNESS_UTILITIES_HPP

#include <fstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <stdexcept>

namespace ut {

typedef std::unordered_set<std::string> string_set;
typedef std::vector<std::string> string_vector;

typedef std::unordered_map<std::string, std::string> str2str;
typedef std::unordered_map<std::string, int> str2num;

typedef std::invalid_argument except;

inline string_set list_loader_v1(const std::string& filename) {
    std::ifstream ifstream(filename);

    if (!ifstream.is_open()) {
        throw except("couldn't open " + filename);
    }

    string_set result;
    std::string element;

    while (std::getline(ifstream, element)) {
        if (element.empty()) {
            continue;
        }
        result.insert(element);
    }

    return result;
}

inline string_vector list_loader_v2(const std::string& filename) {
    std::ifstream ifstream(filename);

    if (!ifstream.is_open()) {
        throw except("couldn't open " + filename);
    }

    string_vector result;
    std::string element;

    while (std::getline(ifstream, element)) {
        if (element.empty()) {
            continue;
        }
        result.push_back(element);
    }

    return result;
}

inline str2str argv_parser_v1(int argc, char* argv[]) {
    str2str map;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg.rfind("-", 0) == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                map[arg] = argv[i + 1];
                ++i;
            } else {
                map[arg];
            }
        } else {
            map["pos" + std::to_string(i)] = arg;
        }
    }

    return map;
}

inline str2num argv_parser_v2(int argc, char* argv[]) {
    str2num map;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg.rfind("-", 0) == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                map[arg] = atoi(argv[i + 1]);
                ++i;
            } else {
                map[arg];
            }
        } else {
            map["pos" + std::to_string(i)]
                = atoi(argv[i]);
        }
    }

    return map;
}

inline void print_at(const std::string& text, int x, int y) {
    std::string line;
    int spaces = 0;

    for (char c : text) {
        if (c == '\n') {
            printf("\033[%d;%dH%s", y, x + spaces, line.c_str());
            ++y;
            line.clear();
            spaces = 0;
        } else if (c == ' ' && line.empty()) {
            ++spaces;
        } else {
            line += c;
        }
    }

    if (!line.empty()) {
        printf("\033[%d;%dH%s", y, x + spaces, line.c_str());
    }
}

} // namespace ut

#endif // WITNESS_UTILITIES_HPP
