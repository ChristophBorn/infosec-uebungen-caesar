#include <stdio.h>

void rot(char* text, int offset) {
    int i = -1;
    while(text[++i]) {
        char a;
        if(text[i] < 'A') { // special
            continue;
        }else if(text[i] <= 'Z') { // A-Z
            a = 'A';
        }else if(text[i] < 'a') { // special
            continue;
        }else if(text[i] <= 'z') { // a-z
            a = 'a';
        }else{ // special
            continue;
        }
        
        text[i] = a + ((text[i] - a + offset) % 26);
    }
}

void encrypt_ceasar (char* text) {
    rot(text, 3);
}

void decrypt_ceasar (char* text) {
    rot(text, -3);
}