/*************************************************************************
 * @file: sm3_complete.c
 * @brief: 国密SM3哈希算法完整实现
 * @author:
 * @version: 1.0
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>

 /* ============================ 数据类型定义 ============================ */

 /**
  * @brief SM3上下文结构体
  * 用于保存哈希计算过程中的中间状态
  */
typedef struct {
    uint32_t total[2];          /*!< 已处理消息的比特数 [0]:低32位, [1]:高32位 */
    uint32_t state[8];          /*!< 中间哈希状态 (A,B,C,D,E,F,G,H) */
    uint8_t buffer[64];         /*!< 正在处理的消息分组 (512比特) */

    /* HMAC相关字段 */
    uint8_t ipad[64];           /*!< HMAC内部填充 */
    uint8_t opad[64];           /*!< HMAC外部填充 */
} sm3_ctx_t;

/* ============================ 常量定义 ============================ */

/**
 * @brief SM3初始哈希值
 * 符合SM3标准规定的初始值
 */
static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

/**
 * @brief 消息填充常量
 * 第一个字节为0x80，其余为0x00
 */
static const uint8_t SM3_PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * @brief 压缩函数中使用的常量Tj
 * 前16轮使用T0=0x79CC4519，后48轮使用T1=0x7A879D8A
 */
static const uint32_t T[64] = {
    /* 0-15轮 */
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    /* 16-63轮 */
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

/* ============================ 宏定义 ============================ */

/**
 * @brief 从字节数组中读取32位大端序整数
 * @param n 输出的32位整数
 * @param b 输入的字节数组
 * @param i 起始位置
 */
#define SM3_GET_U32_BE(n, b, i)                     \
{                                                   \
    (n) = ((uint32_t)(b)[(i)] << 24) |              \
          ((uint32_t)(b)[(i)+1] << 16) |            \
          ((uint32_t)(b)[(i)+2] << 8) |             \
          ((uint32_t)(b)[(i)+3]);                   \
}

 /**
  * @brief 将32位整数写入字节数组（大端序）
  * @param n 输入的32位整数
  * @param b 输出的字节数组
  * @param i 起始位置
  */
#define SM3_PUT_U32_BE(n, b, i)                     \
{                                                   \
    (b)[(i)] = (uint8_t)((n) >> 24);                \
    (b)[(i)+1] = (uint8_t)((n) >> 16);              \
    (b)[(i)+2] = (uint8_t)((n) >> 8);               \
    (b)[(i)+3] = (uint8_t)((n));                    \
}

  /**
   * @brief 循环左移
   * @param x 要移位的32位整数
   * @param n 移位位数
   * @return 循环左移后的结果
   */
#define SM3_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

   /**
    * @brief 布尔函数FFj (0 <= j <= 15)
    * @param x, y, z 输入字
    * @return 布尔函数结果
    */
#define SM3_FF0(x, y, z) ((x) ^ (y) ^ (z))

    /**
     * @brief 布尔函数FFj (16 <= j <= 63)
     * @param x, y, z 输入字
     * @return 布尔函数结果
     */
#define SM3_FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

     /**
      * @brief 布尔函数GGj (0 <= j <= 15)
      * @param x, y, z 输入字
      * @return 布尔函数结果
      */
#define SM3_GG0(x, y, z) ((x) ^ (y) ^ (z))

      /**
       * @brief 布尔函数GGj (16 <= j <= 63)
       * @param x, y, z 输入字
       * @return 布尔函数结果
       */
#define SM3_GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

       /**
        * @brief 置换函数P0
        * @param x 输入字
        * @return 置换结果
        */
#define SM3_P0(x) ((x) ^ SM3_ROTL((x), 9) ^ SM3_ROTL((x), 17))

        /**
         * @brief 置换函数P1
         * @param x 输入字
         * @return 置换结果
         */
#define SM3_P1(x) ((x) ^ SM3_ROTL((x), 15) ^ SM3_ROTL((x), 23))

         /* ============================ 核心函数实现 ============================ */

         /**
          * @brief SM3上下文初始化
          * @param ctx SM3上下文指针
          *
          * 功能：初始化SM3哈希计算的初始状态
          *  - 设置消息长度为0
          *  - 设置初始哈希值IV
          */
void sm3_init(sm3_ctx_t* ctx)
{
    if (ctx == NULL) return;

    /* 初始化消息长度计数器 */
    ctx->total[0] = 0;  /* 低32位 */
    ctx->total[1] = 0;  /* 高32位 */

    /* 设置初始哈希值 */
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));

    /* 清空缓冲区 */
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

/**
 * @brief SM3压缩函数（处理一个512比特分组）
 * @param ctx SM3上下文指针
 * @param data 输入数据（64字节）
 *
 * 功能：对单个消息分组进行压缩计算
 * 步骤：
 *  1. 消息扩展：将16个字扩展为132个字
 *  2. 64轮迭代压缩
 *  3. 更新哈希状态
 */
static void sm3_compress(sm3_ctx_t* ctx, const uint8_t data[64])
{
    uint32_t W[68];     /* 扩展消息字 W0-W67 */
    uint32_t W1[64];    /* 扩展消息字 W'0-W'63 */
    uint32_t A, B, C, D, E, F, G, H;  /* 寄存器变量 */
    uint32_t SS1, SS2, TT1, TT2;      /* 中间变量 */
    int j;

    /* ========== 步骤1：消息扩展 ========== */

    /* 将64字节数据转换为16个32位字（大端序） */
    for (j = 0; j < 16; j++) {
        SM3_GET_U32_BE(W[j], data, j * 4);
    }

    /* 扩展生成W16-W67 */
    for (j = 16; j < 68; j++) {
        uint32_t temp1 = W[j - 16] ^ W[j - 9];
        uint32_t temp2 = SM3_ROTL(W[j - 3], 15);
        uint32_t temp3 = temp1 ^ temp2;
        uint32_t temp4 = SM3_P1(temp3);
        uint32_t temp5 = SM3_ROTL(W[j - 13], 7) ^ W[j - 6];
        W[j] = temp4 ^ temp5;
    }

    /* 生成W'0-W'63 */
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    /* ========== 步骤2：压缩函数迭代 ========== */

    /* 初始化寄存器为当前哈希状态 */
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    /* 前16轮迭代 (0 <= j <= 15) */
    for (j = 0; j < 16; j++) {
        SS1 = SM3_ROTL((SM3_ROTL(A, 12) + E + SM3_ROTL(T[j], j)), 7);
        SS2 = SS1 ^ SM3_ROTL(A, 12);
        TT1 = SM3_FF0(A, B, C) + D + SS2 + W1[j];
        TT2 = SM3_GG0(E, F, G) + H + SS1 + W[j];

        /* 更新寄存器 */
        D = C;
        C = SM3_ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = SM3_ROTL(F, 19);
        F = E;
        E = SM3_P0(TT2);
    }

    /* 后48轮迭代 (16 <= j <= 63) */
    for (j = 16; j < 64; j++) {
        SS1 = SM3_ROTL((SM3_ROTL(A, 12) + E + SM3_ROTL(T[j], j)), 7);
        SS2 = SS1 ^ SM3_ROTL(A, 12);
        TT1 = SM3_FF1(A, B, C) + D + SS2 + W1[j];
        TT2 = SM3_GG1(E, F, G) + H + SS1 + W[j];

        /* 更新寄存器 */
        D = C;
        C = SM3_ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = SM3_ROTL(F, 19);
        F = E;
        E = SM3_P0(TT2);
    }

    /* ========== 步骤3：更新哈希状态 ========== */

    /* 将压缩结果与原始状态异或 */
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

/**
 * @brief 更新SM3哈希计算
 * @param ctx SM3上下文指针
 * @param input 输入数据
 * @param ilen 输入数据长度
 *
 * 功能：处理输入数据，更新哈希状态
 *  - 处理完整的分组（64字节）
 *  - 缓存不足分组的数据
 */
void sm3_update(sm3_ctx_t* ctx, const uint8_t* input, size_t ilen)
{
    size_t fill;
    uint32_t left;

    if (ctx == NULL || input == NULL || ilen == 0) {
        return;
    }

    /* 计算缓冲区中剩余空间 */
    left = ctx->total[0] & 0x3F;  /* total[0] % 64 */
    fill = 64 - left;

    /* 更新消息长度（比特数） */
    ctx->total[0] += (uint32_t)ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    /* 处理32位整数溢出 */
    if (ctx->total[0] < (uint32_t)ilen) {
        ctx->total[1]++;
    }

    /* 如果缓冲区有数据且新数据足够填满一个分组 */
    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        sm3_compress(ctx, ctx->buffer);
        input += fill;
        ilen -= fill;
        left = 0;
    }

    /* 处理完整的分组 */
    while (ilen >= 64) {
        sm3_compress(ctx, input);
        input += 64;
        ilen -= 64;
    }

    /* 将剩余数据存入缓冲区 */
    if (ilen > 0) {
        memcpy(ctx->buffer + left, input, ilen);
    }
}

/**
 * @brief 完成SM3哈希计算，输出最终结果
 * @param ctx SM3上下文指针
 * @param output 输出哈希值（32字节）
 *
 * 功能：完成哈希计算，包括：
 *  - 消息填充
 *  - 处理最后一个分组
 *  - 输出最终哈希值
 */
void sm3_final(sm3_ctx_t* ctx, uint8_t output[32])
{
    uint32_t last, padn;
    uint32_t high, low;
    uint8_t msglen[8];

    if (ctx == NULL || output == NULL) {
        return;
    }

    /* 计算消息长度（比特） */
    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low = (ctx->total[0] << 3);

    /* 将长度转换为大端序字节 */
    SM3_PUT_U32_BE(high, msglen, 0);
    SM3_PUT_U32_BE(low, msglen, 4);

    /* 计算填充长度 */
    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    /* 添加填充 */
    sm3_update(ctx, SM3_PADDING, padn);
    /* 添加消息长度 */
    sm3_update(ctx, msglen, 8);

    /* 输出最终哈希值 */
    SM3_PUT_U32_BE(ctx->state[0], output, 0);
    SM3_PUT_U32_BE(ctx->state[1], output, 4);
    SM3_PUT_U32_BE(ctx->state[2], output, 8);
    SM3_PUT_U32_BE(ctx->state[3], output, 12);
    SM3_PUT_U32_BE(ctx->state[4], output, 16);
    SM3_PUT_U32_BE(ctx->state[5], output, 20);
    SM3_PUT_U32_BE(ctx->state[6], output, 24);
    SM3_PUT_U32_BE(ctx->state[7], output, 28);
}

/**
 * @brief SM3哈希函数（一次性接口）
 * @param input 输入数据
 * @param ilen 输入数据长度
 * @param output 输出哈希值（32字节）
 *
 * 功能：对输入数据计算SM3哈希值
 */
void sm3_hash(const uint8_t* input, size_t ilen, uint8_t output[32])
{
    sm3_ctx_t ctx;

    sm3_init(&ctx);
    sm3_update(&ctx, input, ilen);
    sm3_final(&ctx, output);

    /* 清空上下文，防止信息泄露 */
    memset(&ctx, 0, sizeof(ctx));
}

/* ============================ HMAC-SM3实现 ============================ */

/**
 * @brief HMAC-SM3上下文初始化
 * @param ctx SM3上下文指针
 * @param key HMAC密钥
 * @param keylen 密钥长度
 *
 * 功能：初始化HMAC-SM3计算
 * 步骤：
 *  1. 密钥预处理（过长则哈希，过短则填充）
 *  2. 生成ipad和opad
 *  3. 计算H(K XOR ipad)
 */
void sm3_hmac_init(sm3_ctx_t* ctx, const uint8_t* key, size_t keylen)
{
    uint8_t i_key[64];  /* 处理后的密钥 */
    uint8_t hash[32];   /* 临时哈希值 */
    int i;

    if (ctx == NULL || key == NULL) return;

    /* 密钥过长则先进行哈希 */
    if (keylen > 64) {
        sm3_hash(key, keylen, hash);
        key = hash;
        keylen = 32;
    }

    /* 初始化i_key */
    memset(i_key, 0, sizeof(i_key));
    memcpy(i_key, key, keylen);

    /* 生成ipad和opad */
    memset(ctx->ipad, 0x36, sizeof(ctx->ipad));
    memset(ctx->opad, 0x5C, sizeof(ctx->opad));

    /* 计算K XOR ipad 和 K XOR opad */
    for (i = 0; i < 64; i++) {
        ctx->ipad[i] ^= i_key[i];
        ctx->opad[i] ^= i_key[i];
    }

    /* 开始计算H(K XOR ipad) */
    sm3_init(ctx);
    sm3_update(ctx, ctx->ipad, 64);

    /* 清空敏感数据 */
    memset(i_key, 0, sizeof(i_key));
    memset(hash, 0, sizeof(hash));
}

/**
 * @brief HMAC-SM3数据更新
 * @param ctx SM3上下文指针
 * @param input 输入数据
 * @param ilen 输入数据长度
 */
void sm3_hmac_update(sm3_ctx_t* ctx, const uint8_t* input, size_t ilen)
{
    sm3_update(ctx, input, ilen);
}

/**
 * @brief HMAC-SM3计算完成，输出结果
 * @param ctx SM3上下文指针
 * @param output 输出HMAC值（32字节）
 */
void sm3_hmac_final(sm3_ctx_t* ctx, uint8_t output[32])
{
    uint8_t tmp_hash[32];

    /* 计算H(K XOR ipad || message) */
    sm3_final(ctx, tmp_hash);

    /* 计算H(K XOR opad || H(K XOR ipad || message)) */
    sm3_init(ctx);
    sm3_update(ctx, ctx->opad, 64);
    sm3_update(ctx, tmp_hash, 32);
    sm3_final(ctx, output);

    /* 清空临时数据 */
    memset(tmp_hash, 0, sizeof(tmp_hash));
}

/**
 * @brief HMAC-SM3函数（一次性接口）
 * @param key HMAC密钥
 * @param keylen 密钥长度
 * @param input 输入数据
 * @param ilen 输入数据长度
 * @param output 输出HMAC值（32字节）
 */
void sm3_hmac(const uint8_t* key, size_t keylen,
    const uint8_t* input, size_t ilen,
    uint8_t output[32])
{
    sm3_ctx_t ctx;

    sm3_hmac_init(&ctx, key, keylen);
    sm3_hmac_update(&ctx, input, ilen);
    sm3_hmac_final(&ctx, output);

    memset(&ctx, 0, sizeof(ctx));
}

/* ============================ 工具函数 ============================ */

/**
 * @brief 将字节数组转换为十六进制字符串
 * @param data 字节数组
 * @param len 数据长度
 * @param output 输出字符串缓冲区
 */
void bytes_to_hex(const uint8_t* data, size_t len, char* output)
{
    static const char hex_chars[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        output[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    output[len * 2] = '\0';
}

/**
 * @brief 打印哈希值
 * @param hash 哈希值字节数组
 * @param label 标签
 */
void print_hash(const uint8_t hash[32], const char* label)
{
    char hex[65];
    bytes_to_hex(hash, 32, hex);
    printf("%s:\n%s\n", label, hex);
}

/* ============================ 测试函数 ============================ */

/**
 * @brief SM3算法测试函数
 */
void sm3_test(void)
{
    uint8_t hash[32];
    char hex[65];

    printf("=== SM3算法测试 ===\n\n");

    /* 测试用例1: "abc" */
    const char* test1 = "abc";
    sm3_hash((uint8_t*)test1, strlen(test1), hash);
    print_hash(hash, "SM3(\"abc\")");
    printf("期望: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\n\n");

    /* 测试用例2: 空字符串 */
    const char* test2 = "";
    sm3_hash((uint8_t*)test2, strlen(test2), hash);
    print_hash(hash, "SM3(\"\")");
    printf("期望: 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b\n\n");

    /* 测试用例3: 长字符串 */
    const char* test3 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    sm3_hash((uint8_t*)test3, strlen(test3), hash);
    print_hash(hash, "SM3(16*\"abcd\")");
    printf("期望: debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732\n\n");

    /* HMAC-SM3测试 */
    const char* key = "key";
    const char* message = "message";
    sm3_hmac((uint8_t*)key, strlen(key),
        (uint8_t*)message, strlen(message), hash);
    print_hash(hash, "HMAC-SM3(\"key\", \"message\")");
}

/**
 * @brief 主函数
 */
int main(void)
{
    sm3_test();
    return 0;
}