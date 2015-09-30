
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "sms4.h"

#define GPIO_PATH "/sys/class/gpio_sw/"
#define INH_N   "PG6"
#define OE_N    "PG3"
#define CLK     "PG4"
#define DATA    "PG5"

#define DIRECTION "mul_sel"
#define VALUE "data"
#define INPUT 0
#define OUTPUT 1
#define HIGH 1
#define LOW 0

#define D(...) ((void)0) //printf(__VA_ARGS__)

static int set_gpio(const char *pin, const char *type, int value)
{
    char val = value + 48;
    char path[128] = {0};
    sprintf(path, GPIO_PATH"%s/%s", pin, type);
    D("write  %s %d\n", path, value);

    FILE *fp = fopen(path, "w");
    if (NULL == fp) {
        perror(pin);
        return -1;
    }

    fwrite(&val, 1, 1, fp);

    fclose(fp);
    return 0;
}

//set gpio direction,0-input, 1-output
static int set_dir(const char *pin, int value)
{
    return set_gpio(pin, DIRECTION, value);
}

static int set_value(const char *pin, int value)
{
    return set_gpio(pin, VALUE, value);
}

static int get_value(const char *pin)
{
    char value = -1;
    char path[128] = {0};
    sprintf(path, GPIO_PATH "%s/data", pin);

    FILE *fp = fopen(path, "r");
    if (NULL == fp) {
        perror(pin);
        return -1;
    }

    fread(&value, 1, 1, fp);

    D("read  %s %d\n", path, value - 48);
    fclose(fp);
 
    return value - 48;
}

int enable_WNG4()
{
    D("%s\n", __func__);
    //set INH pin dir:output, disable(1)
    set_dir(INH_N, OUTPUT);
    set_value(INH_N, 1);

    //set OE pin dir:output, enable(0)
    set_dir(OE_N, OUTPUT);
    set_value(OE_N, 0);

    //set CLK pin dir:output
    set_dir(CLK, OUTPUT);

    //set DATA pin dir:input
    set_dir(DATA, INPUT);

    return 0;
}

void disable_WNG4()
{
    //set INH pin dir:output, disable(1)
    set_dir(INH_N, OUTPUT);
    set_value(INH_N, 0);

    //set OE pin dir:output, enable(0)
    set_dir(OE_N, OUTPUT);
    set_value(OE_N, 1);
}

//get a byte random number
char get_byte_random()
{
    unsigned char num = 0;
    int i;
    struct timespec req;
    req.tv_sec = 0;
    req.tv_nsec = 7812; //WNG4 typical output freq:64kbps, MSR:50%

    for (i = 0; i < 8; i++) {
        set_value(CLK, 0);
        nanosleep(&req, NULL);
        set_value(CLK, 1);
        nanosleep(&req, NULL);
        num |= get_value(DATA);
        num <<= 1;
    }

    return num;
}

