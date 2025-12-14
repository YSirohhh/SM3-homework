#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

//  宏定义部分（循环左移、置换函数 P0 / P1）
// 循环左移（x 循环左移 n 位）
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// P0 置换函数：P0(X) = X ^ (X<<<9) ^ (X<<<17)
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))

// P1 置换函数：P1(X) = X ^ (X<<<15) ^ (X<<<23)
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

//  IV 初始向量（SM3 标准固定）

// 初始向量 V0
static const uint32_t IV[8] = {
    0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL,
    0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL};

//  常量 Tj（第 j 轮使用的常数）

// j = 0..15 使用
static const uint32_t Tj_base0 = 0x79cc4519UL;

// j = 16..63 使用
static const uint32_t Tj_base1 = 0x7a879d8aUL;

//  布尔函数 FFj（随 j 改变）
static inline uint32_t FFj(uint32_t x, uint32_t y, uint32_t z, int j)
{
    // 第 0~15 轮：FF = X ^ Y ^ Z
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;

    // 第 16~63 轮：FF = (X & Y) | (X & Z) | (Y & Z)
    return (x & y) | (x & z) | (y & z);
}

//  布尔函数 GGj（随 j 改变）

static inline uint32_t GGj(uint32_t x, uint32_t y, uint32_t z, int j)
{
    // 第 0~15 轮：GG = X ^ Y ^ Z
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;

    // 第 16~63 轮：GG = (X & Y) | ((~X) & Z)
    return (x & y) | ((~x) & z);
}

//  大端序读取和写入 32 位

// 从大端字节序读取一个 32 位整数
static uint32_t GETU32_BE(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) |
           (uint32_t)b[3];
}

// 写一个 32 位整数为大端序
static void PUTU32_BE(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

//  压缩函数（SM3 的核心）
// V 为 256位中间向量，block 为 512bit 数据块（64 字节）
void sm3_compress(uint32_t V[8], const uint8_t block[64])
{
    uint32_t W[68];  // 消息扩展数组 W0..W67
    uint32_t W1[64]; // W1[j] = W[j] ^ W[j+4]

    //  1. 消息扩展 （根据 SM3 标准）
    // 前 16 个字直接取原始消息
    for (int j = 0; j < 16; ++j)
    {
        W[j] = GETU32_BE(block + j * 4);
    }

    // 扩展 W[16..67]
    for (int j = 16; j < 68; ++j)
    {
        uint32_t x = W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15);
        W[j] = P1(x) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }

    // 生成 W1 数组
    for (int j = 0; j < 64; ++j)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

    //  2. 初始化寄存器  (A,B,C,D,E,F,G,H)
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    //  3. 进行 64 轮压缩
    for (int j = 0; j < 64; ++j)
    {
        uint32_t Tj = (j <= 15) ? Tj_base0 : Tj_base1; // 选择对应的 Tj
        uint32_t T_rot = ROTL(Tj, j & 31);             // Tj 循环左移 j 位

        // SS1 = ((A<<<12) + E + (Tj<<<j)) <<< 7
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + T_rot), 7);

        // SS2 = SS1 ^ (A<<<12)
        uint32_t SS2 = SS1 ^ ROTL(A, 12);

        // TT1 = FF(A,B,C) + D + SS2 + W1[j]
        uint32_t TT1 = (FFj(A, B, C, j) + D + SS2 + W1[j]);

        // TT2 = GG(E,F,G) + H + SS1 + W[j]
        uint32_t TT2 = (GGj(E, F, G, j) + H + SS1 + W[j]);

        // 寄存器更新（按标准）
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    //  4. 最终向量 V = V ⊕ ABCDEFGH
    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

//  SM3 哈希函数入口
// msg: 输入消息
// msglen: 消息长度
// out[32]: 输出 32 字节哈希值
void sm3_hash(const uint8_t *msg, size_t msglen, uint8_t out[32])
{
    //  1. 填充消息 （标准 padding）
    uint64_t bitlen = (uint64_t)msglen * 8ULL; // 原文 bit 长度

    // 计算填充 0 的数量：保证末尾剩下 8 字节存放长度
    size_t k = (56 - (msglen + 1) % 64) % 64;

    // 总 padding 长度 = 0x80 + k 个 0x00 + 8 字节长度
    size_t padlen = 1 + k + 8;

    // 填充后的总长度
    size_t total = msglen + padlen;

    // 分配内存
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf)
    {
        fprintf(stderr, "内存分配失败\n");
        return;
    }

    // 复制原文
    memcpy(buf, msg, msglen);
    buf[msglen] = 0x80; // 添加 0x80

    // k 个 0x00
    if (k)
        memset(buf + msglen + 1, 0, k);

    // 写入 64bit 大端序长度
    for (int i = 0; i < 8; ++i)
    {
        buf[msglen + 1 + k + i] = (uint8_t)(bitlen >> (56 - 8 * i));
    }

    //  2. 按每 64 字节一块进行压缩
    uint32_t V[8];
    for (int i = 0; i < 8; ++i)
        V[i] = IV[i];

    size_t blocks = total / 64;

    for (size_t i = 0; i < blocks; ++i)
    {
        sm3_compress(V, buf + i * 64);
    }

    free(buf);

    //  3. 输出哈希值（大端）
    for (int i = 0; i < 8; ++i)
    {
        PUTU32_BE(out + i * 4, V[i]);
    }
}

//  打印十六进制
void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

//  主函数示例
int main(void)
{
    char input[1024]; // 允许输入最长 1023 字符
    uint8_t digest[32];

    printf("请输入要进行 SM3 的字符串（可为空）：\n");

    // 使用 fgets 读取用户输入（可为空）
    if (!fgets(input, sizeof(input), stdin))
    {
        fprintf(stderr, "读取输入失败\n");
        return 1;
    }

    // 去掉末尾的换行符
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n')
        input[len - 1] = '\0';

    // 计算 SM3
    sm3_hash((const uint8_t *)input, strlen(input), digest);

    // 输出结果
    printf("sm3(\"%s\") = ", input);
    print_hex(digest, 32);

    return 0;
}