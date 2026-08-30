#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define VULN_DIR "/sys/devices/system/cpu/vulnerabilities"

// ANSI Escape Codes for Terminal Colors
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_BOLD    "\x1b[1m"

int main() {
    DIR *dir;
    struct dirent *entry;
    char path[512];
    char buffer[1024];

    // Attempt to open the vulnerabilities directory
    dir = opendir(VULN_DIR);
    if (dir == NULL) {
        fprintf(stderr, COLOR_RED "Error:" COLOR_RESET " Could not open %s\n", VULN_DIR);
        fprintf(stderr, "Ensure you are running this on a modern Linux kernel.\n");
        return 1;
    }

    printf(COLOR_BOLD "=== CPU Vulnerability Status ===\n" COLOR_RESET);
    printf("%-20s   %s\n", "VULNERABILITY", "STATUS");
    printf("------------------------------------------------------------\n");

    // Iterate through all files in the directory
    while ((entry = readdir(dir)) != NULL) {
        // Skip current and parent directory pointers
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construct the full file path
        snprintf(path, sizeof(path), "%s/%s", VULN_DIR, entry->d_name);
        
        FILE *fp = fopen(path, "r");
        if (fp != NULL) {
            if (fgets(buffer, sizeof(buffer), fp) != NULL) {
                // Strip the trailing newline character
                buffer[strcspn(buffer, "\n")] = 0;

                // Determine output color based on the status string
                const char *color = COLOR_YELLOW; // Default for unknowns/warnings
                
                if (strstr(buffer, "Vulnerable") != NULL) {
                    color = COLOR_RED;
                } else if (strstr(buffer, "Mitigated") != NULL || strstr(buffer, "Not affected") != NULL) {
                    color = COLOR_GREEN;
                }

                // Print formatted output
                printf("%-20s | %s%s%s\n", entry->d_name, color, buffer, COLOR_RESET);
            }
            fclose(fp);
        }
    }

    closedir(dir);
    return 0;
}
