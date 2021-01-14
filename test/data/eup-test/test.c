#include <stdio.h>
#include <stdlib.h>

void parse_line(char *line) {
    int counts[26] = {0};
    char *ptr = line;
    int idx;

    while (*ptr) {
        idx = (*ptr) - 65;
        if (idx >=0 && idx < 26)
            counts[idx] += 1;
        ptr++;
    }

    for (int i = 0; i < 26; i++)
        printf("%d ", counts[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    FILE *ifile = NULL;
    char *line = NULL;
    size_t size = 0;

    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }

    ifile = fopen(argv[1], "r");
    if (!ifile)
        return 1;

    while (getline(&line, &size, ifile) != -1)
        parse_line(line);

    if (line)
        free(line);

    fclose(ifile);

    return 0;
}
