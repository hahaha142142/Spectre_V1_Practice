#include <stdio.h>
#include "Victim.h"

//攻击者数组
extern unsigned char attacker_array[256*Cache_Line];
//受害者数组
static unsigned char victim_array[5] = {0};
//受害者数组大小
unsigned char victim_array_size = 5;
//临时变量
static unsigned char temp = 0;
//秘密信息
const static char* secret = "Secret{XXXXXXXXXX}";

struct Information get_victim_information(){
    struct Information information = {(unsigned long long)secret, (unsigned long long)victim_array};
    return information;
}

void victim(unsigned long long attacker_index){
    //Spectre攻击的核心代码
    if(attacker_index < victim_array_size) temp = attacker_array[victim_array[attacker_index]*Cache_Line];
}
