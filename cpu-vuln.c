#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#define IA32_SPEC_CTRL_MSR 0x48

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

    // Print CPU Information
    print_cpu_info();

    // The msr driver maps the file offset directly to the MSR register index
    printf(COLOR_BOLD COLOR_CYAN "=== CPU Hardware Mitigations ===\n" COLOR_RESET);
    int fd = open("/dev/cpu/0/msr", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/cpu/0/msr\n(Tip: Run with sudo and ensure 'modprobe msr' is loaded)");
        return 1;
    }

    uint64_t spec_ctrl = 0;
    
    // Read 8 bytes (64-bit MSR) using the MSR address as the file offset
    if (pread(fd, &spec_ctrl, sizeof(spec_ctrl), IA32_SPEC_CTRL_MSR) != sizeof(spec_ctrl)) {
        perror("Failed to read IA32_SPEC_CTRL MSR");
        close(fd);
        return 1;
    }
    
    close(fd);

    // Isolate active control bits
    int ibrs_active  = (spec_ctrl & (1ULL << 0)) != 0; // Bit 0: Indirect Branch Restricted Speculation
    int stibp_active = (spec_ctrl & (1ULL << 1)) != 0; // Bit 1: Single Thread Indirect Branch Predictors
    int ssbd_active  = (spec_ctrl & (1ULL << 2)) != 0; // Bit 2: Speculative Store Bypass Disable

    printf("IA32_SPEC_CTRL (0x48) Raw Value: 0x%016lx\n", spec_ctrl);
    printf("----------------------------------------\n");
    printf("  IBRS Active  : %s\n", ibrs_active ? "Yes" : "No");
    printf("  STIBP Active : %s\n", stibp_active ? "Yes" : "No");
    printf("  SSBD Active  : %s\n", ssbd_active ? "Yes" : "No");
    printf("\n");

    // Open and parse vulnerabilities directory
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