#ifndef VICTIM_H
#define VICTIM_H

//预设的L3缓存行大小
#define Cache_Line 4096

//该结构体内包含秘密信息的地址和受害者数组的地址
struct Information{
    unsigned long long Secret_Address;
    unsigned long long Victim_Array_Address;
};

//获取受害者程序的一些信息
struct Information get_victim_information();

//被攻击的受害者程序段
void victim(unsigned long long attacker_index);

#endif
