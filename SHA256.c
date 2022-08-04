/* SHA256.c -- implement SHA-256 algorithm */
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define rightrotate(w, n) ((w >> n) | (w) << (32-(n)))

typedef unsigned char BYTE;         // 8-bit byte
typedef uint32_t  WORD;             // 32-bit word, change to "long" for 16-bit machines

// Initialize array of round constants:
static const WORD k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256(const unsigned char *data, size_t len, unsigned char *out);

int main(void)
{
  // const unsigned char message[] = { 'a', 'b', 'c' };
  const unsigned char *message = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

  unsigned char *text;

  // sha256(message, sizeof message, text);
  sha256(message, 1024, text);

  for (int i = 0; i < 32; i++)
  {
    printf("%02x", *(text + i));
  }

  return 0;
}

void sha256(const unsigned char *data, size_t len, unsigned char *out)
{
  // Initialize hash values:
  uint32_t h0 = 0x6a09e667;
  uint32_t h1 = 0xbb67ae85;
  uint32_t h2 = 0x3c6ef372;
  uint32_t h3 = 0xa54ff53a;
  uint32_t h4 = 0x510e527f;
  uint32_t h5 = 0x9b05688c;
  uint32_t h6 = 0x1f83d9ab;
  uint32_t h7 = 0x5be0cd19;

  // 计算需要补码的数量
  int r = (int)(len * 8 % 512);
  int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8; // 若最后一个消息块长度等于448则需要再补512位

  // 源数据长度 + 需要补充的长度 + 8(末尾原数据长度信息的长度 64位) = 预处理后的数据长度
  size_t new_len = len + append + 8;
  
  unsigned char buf[new_len];

  // void bzero(void *s, int n);将指定内存块的前n个字节全部设置为零。 s为内存（字符串）指针，所指定内存块的首地址，n 为需要清零的字节数。
  // 把buf数组中len长度后的存储区全部设置为0
  // bzero(buf + len, append);
  memset(buf + len, 0, append); // 用memset代替

  // 若源数据长度大于0
  if (len > 0) {
    // C 库函数 void *memcpy(void *str1, const void *str2, size_t n) 从存储区 str2 复制 n 个字节到存储区 str1。
    // 把源数据放置到该数组
    memcpy(buf, data, len);
  }

  // 在源数据末尾补1000 0000 也就是0x80
  buf[len] = (unsigned char)0x80;

  // 源数据的的bit数
  uint64_t bits_len = len * 8;

  // 在buf末尾保存源数据长度信息 大端序
  for (int i = 0; i < 8; i++)
  { // 从倒数第64位开始遍历，也就是要保存长度信息段的开头开始
    // 源数据bit数右移8减去现在遍历到的所在字节 也就是说，遍历到这个64位的第几位中就保存bitlen的第几位
    buf[len + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff; // & 0xff是为了只保留最后八位二进制数
  }

  // 每个块需要被分成64份32bit字的数组 其中前16个元素是直接分解当前所需要被分块的块
  uint32_t w[64];

  // 把w数组全置0
  // bzero(w, 64);
  memset(w, 0, 64); // 用memset代替

  // 块数量 因为每个块都要被分成64份所以这里采用除以64
  size_t chunk_sum = new_len / 64;

  // 遍历每个消息块
  for (int idx = 0; idx < chunk_sum; idx++) {

    // 以下为计算前每个块中前16个元素的值与剩余48个元素的计算步骤
    // 初始化一个缓存变量
    uint32_t val = 0;

    // 对于每一块，将块分解为16个32-bit的big-endian的字
    for (int i = 0; i < 64; i++) {
      // 指针+1所增加的地址值为这个指针类型所占用的内存大小的值
      // val | (指针(地址) 也就是buf数组当前所遍历到的块的第i个8bit的内存位置 << 左移8*他所在需要被分配到当前32位元素中的buf中的4个元素中的倒数第几位)
      val =  val | (*(buf + idx * 64 + i) << (8 * (3 - i)));
      if (i % 4 == 3) { // 这里保证每过4*8=32位存入w的第1至16个位置 相当于每循环4次保存一次
        w[i / 4] = val;
        val = 0;  // 重置缓存变量
      }
    }

    // 计算剩余的48个元素 Wj = σ1 + Wj-7 + σ0 + Wj-16
    for (int i = 16; i < 64; i++) {
      // σ0(x)=S7(x)⊕S18(x)⊕R3(x)
      uint32_t s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
      // σ1(x)=S17(x)⊕S19(x)⊕R10(x)
      uint32_t s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
      // Wj = σ1 + Wj-7 + σ0 + Wj-16
      w[i] = s1 + w[i - 7] + s0 + w[i - 16];
    }
    // 以上为计算前每个块中前16个元素的值与剩余48个元素的计算步骤

    // 以下为主要计算逻辑
    // 设置初始化值 若为第一个消息块，则采用初始化值
    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;
    uint32_t f = h5;
    uint32_t g = h6;
    uint32_t h = h7;

    for (int i = 0; i < 64; i++) {
      /* Update working variables as:
        h = g
        g = f
        f = e
        e = d + Temp1
        d = c
        c = b
        b = a
        a = Temp1 + Temp2
        Where
        Temp1 = h + Σ1 + Choice + Ki + Wi
        Temp2 = Σ0 + Majority
        Σ1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        Choice = (e and f) xor ((not e) and g)
        Σ0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        Majority = (a and b) xor (a and c) xor (b and c)
      */

      // Σ1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
      uint32_t s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);

      // Choice = (e and f) xor ((not e) and g)
      uint32_t ch = (e & f) ^ (~e & g);

      // Temp1 = h + Σ1 + Choice + Ki + Wi
      uint32_t temp1 = h + s_1 + ch + k[i] + w[i];

      // Σ0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
      uint32_t s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);

      // Majority = (a and b) xor (a and c) xor (b and c)
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);

      // Temp2 = Σ0 + Majority
      uint32_t temp2 = s_0 + maj;

      // if (i == 4) {
        // printf("%d %x %x %x\n", i, (a & b), (a & c), (b & c));
        // printf("%d %x %x %x %x %x %x %x %x\n", i, a, b, c, d, e, f, g, h);
      // }

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    // 为下个消息块计算中间哈希值保存其初始值
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
  }

  uint32_t hex[8] = { h0, h1, h2, h3, h4, h5, h6, h7 };
  
  // for (int i = 0; i < 8; i++)
  // {
  //   uint32_t temp = hex[i];

  //   printf("%08x", temp);
  // }
  // printf("\n");

  // 置0
  memset(out, 0, 32); // 用memset代替

  // 遍历hex的8个元素也就是8*32 = 256bit = 256 / 8 = 32bytes
  for (int i = 0; i < 32; i++)
  {
    // hex+(i/4)因为一个hex元素要被分成4等份的元素 32bit/4=8bit 因为一个32bit的4个char
    // 依次移位24、16、8、0
    *(out + i) = (*(hex + (i / 4)) >> (8 * (3 - (i%4)))) & 0xff;
  }
}