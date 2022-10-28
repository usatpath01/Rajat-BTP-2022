#include <stdio.h>
#include <unistd.h>

int main()
{
    FILE *fp = fopen("out.txt", "w");
    fprintf(fp,"Hello Stdout!\n");
    fprintf(stderr, "Hello Error!!\n");
}