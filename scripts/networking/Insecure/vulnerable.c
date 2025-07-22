#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void spawn_shell() {
    printf("Spawning shell...\n");
    system("/bin/sh");
}

void vulnerable_function(char *user_input) {
    char buffer[64];
    printf("Buffer address: %p\n", buffer);
    printf("spawn_shell() address: %p\n", spawn_shell);
    printf("Input: %s\n", user_input);
    strcpy(buffer, user_input);
    printf("Copia completata\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Uso: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
