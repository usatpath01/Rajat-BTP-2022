#include <stdio.h>
#include <unistd.h>

int main()
{
    printf("Hello Stdout!\n");
    fprintf(stderr, "Hello Error!!\n");
}