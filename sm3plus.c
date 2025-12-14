#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

//  宏定义部分（循环左移、置换函数 P0 / P1）
// 循环左移（x 循环左移 n 位）
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// P0 置换函数：P0(X) = X ^ (X<<<9) ^ (X<<<17)
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))

// P1 置换函数：P1(X) = X ^ (X<<<15) ^ (X<<<23)
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

//  IV 初始向量（SM3 标准固定）
static const uint32_t IV[8] = {
    0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL,
    0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL};

// 常量 Tj
static const uint32_t Tj_base0 = 0x79cc4519UL;
static const uint32_t Tj_base1 = 0x7a879d8aUL;

// 布尔函数 FFj
static inline uint32_t FFj(uint32_t x, uint32_t y, uint32_t z, int j)
{
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

// 布尔函数 GGj
static inline uint32_t GGj(uint32_t x, uint32_t y, uint32_t z, int j)
{
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

// 大端序读取和写入
static uint32_t GETU32_BE(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) |
           (uint32_t)b[3];
}

static void PUTU32_BE(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

// 压缩函数
void sm3_compress(uint32_t V[8], const uint8_t block[64])
{
    uint32_t W[68];
    uint32_t W1[64];

    for (int j = 0; j < 16; ++j)
    {
        W[j] = GETU32_BE(block + j * 4);
    }

    for (int j = 16; j < 68; ++j)
    {
        uint32_t x = W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15);
        W[j] = P1(x) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }

    for (int j = 0; j < 64; ++j)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; ++j)
    {
        uint32_t Tj = (j <= 15) ? Tj_base0 : Tj_base1;
        uint32_t T_rot = ROTL(Tj, j & 31);

        uint32_t SS1 = ROTL((ROTL(A, 12) + E + T_rot), 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (FFj(A, B, C, j) + D + SS2 + W1[j]);
        uint32_t TT2 = (GGj(E, F, G, j) + H + SS1 + W[j]);

        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

// SM3 哈希函数
void sm3_hash(const uint8_t *msg, size_t msglen, uint8_t out[32])
{
    uint64_t bitlen = (uint64_t)msglen * 8ULL;
    size_t k = (56 - (msglen + 1) % 64) % 64;
    size_t padlen = 1 + k + 8;
    size_t total = msglen + padlen;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf)
    {
        fprintf(stderr, "内存分配失败\n");
        return;
    }

    memcpy(buf, msg, msglen);
    buf[msglen] = 0x80;

    if (k)
        memset(buf + msglen + 1, 0, k);

    for (int i = 0; i < 8; ++i)
    {
        buf[msglen + 1 + k + i] = (uint8_t)(bitlen >> (56 - 8 * i));
    }

    uint32_t V[8];
    for (int i = 0; i < 8; ++i)
        V[i] = IV[i];

    size_t blocks = total / 64;
    for (size_t i = 0; i < blocks; ++i)
    {
        sm3_compress(V, buf + i * 64);
    }

    free(buf);

    for (int i = 0; i < 8; ++i)
    {
        PUTU32_BE(out + i * 4, V[i]);
    }
}

// 打印十六进制
void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02x", buf[i]);
    }
}

// 生成随机字符串
void generate_random_string(uint8_t *buffer, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        buffer[i] = (uint8_t)(rand() % 256);
    }
}

// 抗碰撞性测试
void collision_resistance_test()
{
    printf("==================== 抗碰撞性测试 ====================\n");
    printf("生成 10000 个随机字符串（长度 16-256 字节）\n");
    printf("计算 SM3 哈希值，检查是否有碰撞\n\n");

    srand((unsigned int)time(NULL));

// 使用简单的哈希表来检测碰撞
#define MAX_HASHES 10000
    uint8_t hashes[MAX_HASHES][32];
    int collisions = 0;
    int duplicate_hits = 0;

    clock_t start = clock();

    for (int i = 0; i < MAX_HASHES; i++)
    {
        // 生成长度在 16-256 字节之间的随机字符串
        size_t length = 16 + rand() % 241;
        uint8_t *message = (uint8_t *)malloc(length);

        if (!message)
        {
            fprintf(stderr, "内存分配失败\n");
            continue;
        }

        generate_random_string(message, length);

        // 计算 SM3 哈希值
        sm3_hash(message, length, hashes[i]);

        // 检查是否与之前的哈希值冲突
        for (int j = 0; j < i; j++)
        {
            if (memcmp(hashes[i], hashes[j], 32) == 0)
            {
                collisions++;
                duplicate_hits++;

                if (collisions <= 5) // 只显示前5个碰撞
                {
                    printf("发现碰撞 #%d:\n", collisions);
                    printf("字符串 %d (长度 %zu) 和字符串 %d (长度 %zu) 产生相同哈希值\n",
                           i, length, j, length);
                    printf("哈希值: ");
                    print_hex(hashes[i], 32);
                    printf("\n\n");
                }
                break;
            }
        }

        free(message);
    }

    clock_t end = clock();
    double time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    printf("测试完成！\n");
    printf("测试字符串数量: %d\n", MAX_HASHES);
    printf("发现碰撞数量: %d\n", collisions);
    printf("重复检测次数: %d\n", duplicate_hits);
    printf("测试耗时: %.2f 秒\n", time_used);
    printf("碰撞率: %.6f%%\n", (double)collisions / MAX_HASHES * 100);
    printf("====================================================\n\n");
}

// 统计两个哈希值之间的比特差异
int count_bit_differences(const uint8_t *hash1, const uint8_t *hash2)
{
    int diff_count = 0;

    for (int i = 0; i < 32; i++)
    {
        uint8_t xor_result = hash1[i] ^ hash2[i];

        // 统计 XOR 结果中的1的个数（即不同的比特数）
        while (xor_result)
        {
            diff_count += (xor_result & 1);
            xor_result >>= 1;
        }
    }

    return diff_count;
}

// 翻转指定位置的比特
void flip_bit(uint8_t *message, size_t byte_pos, int bit_pos)
{
    if (byte_pos < 256) // 安全检查
    {
        message[byte_pos] ^= (1 << bit_pos);
    }
}

// 打印比特差异可视化
void print_bit_difference_visual(const uint8_t *hash1, const uint8_t *hash2, int max_bits)
{
    printf("比特差异可视化: ");
    for (int i = 0; i < max_bits && i < 32 * 8; i++)
    {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8); // 从高位到低位
        int bit1 = (hash1[byte_idx] >> bit_idx) & 1;
        int bit2 = (hash2[byte_idx] >> bit_idx) & 1;

        if (bit1 != bit2)
            printf("X");
        else
            printf(".");

        if ((i + 1) % 64 == 0 && i < max_bits - 1)
            printf("\n                    ");
    }
    printf("\n");
}

// 雪崩效应测试
void avalanche_effect_test()
{
    printf("==================== 雪崩效应测试 ====================\n");
    printf("基础输入: \"sm3_avalanche_test_2024\"\n");
    printf("测试要求: 1比特变化应导致至少128比特（50%）变化\n\n");

    const char *base_input = "sm3_avalanche_test_2024";
    size_t input_len = strlen(base_input);

    printf("原始输入长度: %zu 字节 (%zu 比特)\n", input_len, input_len * 8);
    printf("SM3输出长度: 256 比特\n\n");

    // 计算原始输入的哈希值
    uint8_t original_hash[32];
    sm3_hash((const uint8_t *)base_input, input_len, original_hash);

    printf("原始输入哈希值 H0: ");
    print_hex(original_hash, 32);
    printf("\n\n");

    int test_cases = 5;
    int total_diff_bits = 0;
    int test_positions[5][2] = {
        {0, 0},  // 第1个字节的第1个比特（最高位）
        {0, 7},  // 第1个字节的第8个比特（最低位）
        {5, 3},  // 第6个字节的第4个比特
        {10, 1}, // 第11个字节的第2个比特
        {18, 5}  // 第19个字节的第6个比特（最后一个字节）
    };

    printf("开始 %d 次比特翻转测试:\n", test_cases);
    printf("--------------------------------------------------------\n");

    for (int test = 0; test < test_cases; test++)
    {
        // 创建原始输入的副本
        uint8_t modified_input[256];
        memcpy(modified_input, base_input, input_len + 1);

        int byte_pos = test_positions[test][0];
        int bit_pos = test_positions[test][1];

        if (byte_pos >= input_len)
        {
            printf("警告: 测试位置 %d 超出输入长度，跳过\n", byte_pos);
            continue;
        }

        // 记录原始字节值
        uint8_t original_byte = modified_input[byte_pos];

        // 翻转指定比特
        flip_bit(modified_input, byte_pos, bit_pos);

        // 计算修改后的哈希值
        uint8_t modified_hash[32];
        sm3_hash(modified_input, input_len, modified_hash);

        // 统计比特差异
        int diff_bits = count_bit_differences(original_hash, modified_hash);
        total_diff_bits += diff_bits;

        // 打印测试结果
        printf("测试 #%d:\n", test + 1);
        printf("原始输入: %s\n", base_input);
        printf("修改位置: 第 %d 字节，第 %d 比特\n", byte_pos + 1, bit_pos + 1);
        printf("原始字节: 0x%02x, 修改后: 0x%02x\n",
               original_byte, modified_input[byte_pos]);
        printf("修改后输入: ");
        print_hex(modified_input, input_len);
        printf("\n");
        printf("H0: ");
        print_hex(original_hash, 32);
        printf("\n");
        printf("H1: ");
        print_hex(modified_hash, 32);
        printf("\n");
        printf("差异比特数: %d/256 (%.2f%%)\n",
               diff_bits, (float)diff_bits / 256 * 100);

        // 显示比特差异可视化（前128位）
        print_bit_difference_visual(original_hash, modified_hash, 128);

        // 检查是否满足雪崩效应
        if (diff_bits >= 128)
        {
            printf("? 满足雪崩效应 (≥128比特差异)\n");
        }
        else
        {
            printf("? 不满足雪崩效应 (<128比特差异)\n");
        }

        printf("--------------------------------------------------------\n");
    }

    double avg_diff_bits = (double)total_diff_bits / test_cases;

    printf("\n测试总结:\n");
    printf("总测试次数: %d\n", test_cases);
    printf("总差异比特数: %d\n", total_diff_bits);
    printf("平均差异比特数: %.2f/256 (%.2f%%)\n",
           avg_diff_bits, avg_diff_bits / 256 * 100);

    if (avg_diff_bits >= 128)
    {
        printf("? 平均雪崩效应: 强 (≥128比特)\n");
    }
    else if (avg_diff_bits >= 100)
    {
        printf("? 平均雪崩效应: 中等 (100-127比特)\n");
    }
    else
    {
        printf("? 平均雪崩效应: 弱 (<100比特)\n");
    }

    printf("====================================================\n\n");
}

// 主函数
int main(void)
{
    printf("=============== SM3 哈希算法测试程序 ===============\n\n");

    // 测试菜单
    int choice;
    do
    {
        printf("请选择测试项目:\n");
        printf("1. 单字符串 SM3 计算\n");
        printf("2. 抗碰撞性测试\n");
        printf("3. 雪崩效应测试\n");
        printf("4. 运行所有测试\n");
        printf("0. 退出\n");
        printf("请选择 (0-4): ");

        scanf("%d", &choice);
        getchar(); // 清除换行符

        switch (choice)
        {
        case 1:
        {
            printf("\n=============== 单字符串 SM3 计算 ===============\n");
            char input[1024];
            uint8_t digest[32];

            printf("请输入要进行 SM3 的字符串（可为空）：\n");

            if (!fgets(input, sizeof(input), stdin))
            {
                fprintf(stderr, "读取输入失败\n");
                break;
            }

            size_t len = strlen(input);
            if (len > 0 && input[len - 1] == '\n')
                input[len - 1] = '\0';

            sm3_hash((const uint8_t *)input, strlen(input), digest);

            printf("sm3(\"%s\") = ", input);
            print_hex(digest, 32);
            printf("\n");
            printf("================================================\n\n");
            break;
        }

        case 2:
            collision_resistance_test();
            break;

        case 3:
            avalanche_effect_test();
            break;

        case 4:
            printf("\n");
            collision_resistance_test();
            avalanche_effect_test();
            break;

        case 0:
            printf("程序退出。\n");
            break;

        default:
            printf("无效选择，请重新输入。\n");
            break;
        }

    } while (choice != 0);

    return 0;
}