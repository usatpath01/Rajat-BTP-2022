#include <stdio.h>
#include <unistd.h>

int main()
{
    FILE *fp = fopen("out.txt", "w");
    printf("Hello Stdout. Hello Stdout. Hello Stdout. Hello Stdout. Hello Stdout. Hello Stdout. Hello Stdout. Hello Stdout. Hello Stdout. Hello Stdout.");
    fprintf(stderr, "Hello Error!!\n");
}