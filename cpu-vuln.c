#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define VULN_DIR "/sys/devices/system/cpu/vulnerabilities"
#define CPUINFO_FILE "/proc/cpuinfo"

// ANSI Escape Codes for Terminal Colors
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_BOLD    "\x1b[1m"

// Function to parse and print CPU model and microcode
void print_cpu_info() {
    FILE *fp = fopen(CPUINFO_FILE, "r");
    if (fp == NULL) {
        fprintf(stderr, COLOR_RED "Error:" COLOR_RESET " Could not open %s\n", CPUINFO_FILE);
        return;
    }

    char line[256];
    char model_name[128] = "Unknown";
    char microcode[64] = "Unknown";
    int found_model = 0, found_ucode = 0;

    // Scan file line by line until both values are found
    while (fgets(line, sizeof(line), fp)) {
        if (!found_model && strncmp(line, "model name", 10) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                strncpy(model_name, colon + 2, sizeof(model_name));
                model_name[strcspn(model_name, "\n")] = 0; // Strip newline
                found_model = 1;
            }
        } else if (!found_ucode && strncmp(line, "microcode", 9) == 0) {
            char *colon = strchr(line, ':');
            if (colon) {
                strncpy(microcode, colon + 2, sizeof(microcode));
                microcode[strcspn(microcode, "\n")] = 0; // Strip newline
                found_ucode = 1;
            }
        }
        
        if (found_model && found_ucode) break;
    }
    fclose(fp);

    printf(COLOR_BOLD COLOR_CYAN "=== CPU Hardware Info ===\n" COLOR_RESET);
    printf(COLOR_BOLD "Processor: " COLOR_RESET "%s\n", model_name);
    printf(COLOR_BOLD "Microcode: " COLOR_RESET "%s\n\n", microcode);
}

int main() {
    DIR *dir;
    struct dirent *entry;
    char path[512];
    char buffer[1024];

    // 1. Print CPU Information
    print_cpu_info();

    // 2. Open and parse vulnerabilities directory
    dir = opendir(VULN_DIR);
    if (dir == NULL) {
        fprintf(stderr, COLOR_RED "Error:" COLOR_RESET " Could not open %s. Are you on a modern Linux kernel?\n", VULN_DIR);
        return 1;
    }

    printf(COLOR_BOLD COLOR_CYAN "=== CPU Vulnerability Status ===\n" COLOR_RESET);
    printf("%-22s   %s\n", "VULNERABILITY", "STATUS");
    printf("------------------------------------------------------------\n");

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", VULN_DIR, entry->d_name);
        
        FILE *fp = fopen(path, "r");
        if (fp != NULL) {
            if (fgets(buffer, sizeof(buffer), fp) != NULL) {
                buffer[strcspn(buffer, "\n")] = 0;

                const char *color = COLOR_YELLOW; 
                
                if (strstr(buffer, "Vulnerable") != NULL) {
                    color = COLOR_RED;
                } else if (strstr(buffer, "Mitigated") != NULL || strstr(buffer, "Not affected") != NULL) {
                    color = COLOR_GREEN;
                }

                printf("%-22s | %s%s%s\n", entry->d_name, color, buffer, COLOR_RESET);
            }
            fclose(fp);
        }
    }

    closedir(dir);
    return 0;
}