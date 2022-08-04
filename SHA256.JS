function SHA256(data) {
  // 初始值
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  // 所需的64个常量
  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  // 转换为指定位数的某进制字符串
  function transferToStr(number, digit, radix) {
    let tempStr = number.toString(radix); // 转换为2进制字符串
    // 在字符串开头补0
    let bitsLengthBinStrAppendSum = digit - tempStr.length;
    for (let i = 0; i < bitsLengthBinStrAppendSum; i++) {
      tempStr = '0'+tempStr;
    }
    return tempStr;
  }

  function rightrotate(w, n) { // 模拟32位无符号整数循环右移
    let tempStr = transferToStr(w, 32, 2);

    let tempArr = tempStr.split('');

    while (n--) { // 循环右移
      tempArr.unshift(tempArr.pop());
    }

    return parseInt(tempArr.join(''), 2);
  }

  function xorStr32(x, y) { // 模拟32位无符号整数异或运算
    let xStr = transferToStr(x, 32, 2); // 转换为2进制字符串
    let yStr = transferToStr(y, 32, 2); // 转换为2进制字符串

    let xArr = xStr.split('');
    let yArr = yStr.split('');

    let tempArr = [];

    for (let idx = 0; idx < 32; idx++) {
      tempArr.push(xArr[idx] !== yArr[idx] ? '1' : '0');
    }

    return parseInt(tempArr.join(''), 2);
  }

  function andStr32(x, y) { // 模拟32位无符号整数与运算
    let xStr = transferToStr(x, 32, 2); // 转换为2进制字符串
    let yStr = transferToStr(y, 32, 2); // 转换为2进制字符串

    let xArr = xStr.split('');
    let yArr = yStr.split('');

    let tempArr = [];

    for (let idx = 0; idx < 32; idx++) {
      tempArr.push(xArr[idx] === '1' && yArr[idx] === '1' ? '1' : '0');
    }

    return parseInt(tempArr.join(''), 2);
  }

  function notStr32(x) { // 模拟32位无符号整数非运算
    let xStr = transferToStr(x, 32, 2); // 转换为2进制字符串

    let xArr = xStr.split('');

    let tempArr = [];

    for (let idx = 0; idx < 32; idx++) {
      tempArr.push(xArr[idx] !== '1' ? '1' : '0');
    }

    return parseInt(tempArr.join(''), 2);
  }

  function addition32bit(x, y) { // 32位无符号整数加法运算，超出32位作为溢出处理 因为js默认以64位保存，溢出部分也会被保存到变量 这里要舍弃
    let result = x + y;

    let str = result.toString(16);

    if (str.length > 8) { // 超出多少位去除开头多少位
      str = str.substr(str.length-8);
    }

    return parseInt(str, 16);
  }
  // 将源数据转为字符串
  const dataStr = data.toString();
  // 将源数据字符串转为ASCII码值数组
  const charArr = dataStr.split('').map(char => char.charCodeAt(0));
  // 获取源数据长度
  const dataLength = charArr.length;

  // 计算数据长度或超出512bit后的长度，以此为基础计算需要补充的位数
  const r = dataLength * 8 % 512;
  // 计算需要补充的位数 若低于448则补充至448即可否则再加512再计算需要补充的位数，因为512-448=64位是为了记录源数据长度的
  const append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;

  // 源数据长度 + 需要补充的长度 + 8(末尾原数据长度信息的长度 64位) = 预处理后的数据长度 这里单位是字节 512bit=64bytes
  const newLength = dataLength + append + 8;
  
  // buffer数组 一个元素为一个字节长度
  let buf = new Array(newLength);

  // 把buf数组中的存储区全部设置为0
  for (let i = 0; i < newLength; i++) {
    buf[i] = 0;
  }

  // 若源数据长度大于0
  if (dataLength > 0) {
    // 把源数据放置到该数组
    for (let i = 0; i < dataLength; i++) {
      buf[i] = charArr[i];
    }
  }

  // 在源数据末尾补1000 0000 也就是0x80 因为是字节为单位的，而且补完1之后就要补0，所以这里直接设为0x80也就是十进制的128
  buf[dataLength] = 0x80;

  // 源数据的的bit数 这里认为其是64位数据
  // JavaScript的Number类型遵循的是IEEE 754规范中的双精度储存，不分浮点型和整型，所以在js中，1===1.0 而整数运算会自动转化为32位有符号整数
  // 这里直接转换成字符串来使其成为16位16制数字符串，然后再分割遍历转换为数组存入buf 16位16进制数等于64个bit（2位16进制数等于1byte=8bit）
  let bitsLengthBinStr = (dataLength * 8).toString(16); // 转化2进制字符串
  let bitsLengthBinStrAppendSum = 16 - bitsLengthBinStr.length;
  for (let i = 0; i < bitsLengthBinStrAppendSum; i++) {
    bitsLengthBinStr = '0'+bitsLengthBinStr;
  }
  
  // 在buf末尾保存源数据长度信息 大端序
  for (let i = 0; i < 8; i++) { // 从倒数第64位开始遍历，也就是要保存长度信息段的开头开始
    // 源数据bit数右移8减去现在遍历到的所在字节 也就是说，遍历到这个64位的第几位中就保存bitlen的第几位
    // buf[dataLength + append + i] = (bitsLength >> ((7 - i) * 8)) & 0xff; // & 0xff是为了只保留最后八位二进制数
    buf[dataLength + append + i] = parseInt(bitsLengthBinStr.match(/.{1,2}/g)[i], 16); // 利用正则表达式按2位分割字符串为数组
  }

  // 每个块需要被分成64份32bit字的数组 其中前16个元素是直接分解当前所需要被分块的块
  const w = new Array(64);

  // 把w数组中的存储区全部设置为0
  for (let i = 0; i < w.length; i++) {
    w[i] = 0;
  }

  // 计算消息块数量 因为每个块都要被分成64份所以这里采用除以64
  const chunkSum = newLength / 64;

  // 遍历每个消息块
  for (let idx = 0; idx < chunkSum; idx++) {
    // 计算前每个块中前16个元素的值与剩余48个元素

    let temp = 0; // 用于存入前16个元素的缓存变量
    for (let i = 0; i < 64; i++) { 
      // 处理后的源数据分为16份放入w中 因为是要把4个8bit的数据存为一个32bit的元素，所以这里进行移位处理
      // 笨方法，还是可以使用操作字符串的形式解决
      temp = temp | buf[idx * 64 + i] << (8 * (3 - i));
      if (i % 4 == 3) { // 这里保证每过4*8=32位存入w的第1至16个位置 相当于每循环4次保存一次
        w[parseInt(i / 4)] = temp;
        temp = 0;  // 重置缓存变量
      }
    }

    // 计算剩余的48个元素 Wj = σ1 + Wj-7 + σ0 + Wj-16
    for (let i = 16; i < 64; i++) {
      // σ0(x)=S7(x)⊕S18(x)⊕R3(x)
      // let s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
      let s0 = xorStr32(xorStr32(rightrotate(w[i - 15], 7), rightrotate(w[i - 15], 18)), (w[i - 15] >>> 3));
      // σ1(x)=S17(x)⊕S19(x)⊕R10(x)
      // let s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
      let s1 = xorStr32(xorStr32(rightrotate(w[i - 2], 17), rightrotate(w[i - 2], 19)), (w[i - 2] >>> 10));
      // Wj = σ1 + Wj-7 + σ0 + Wj-16
      // w[i] = s1 + w[i - 7] + s0 + w[i - 16];
      w[i] = addition32bit(addition32bit(addition32bit(s1, w[i - 7]), s0), w[i - 16]);
    }
    
    // 设置初始化值 若为第一个消息块，则采用初始化值
    // 这些计算单位都按无符号32位处理
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      // Σ1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
      // let s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
      let s_1 = xorStr32(xorStr32(rightrotate(e, 6), rightrotate(e, 11)), rightrotate(e, 25));

      // Choice = (e and f) xor ((not e) and g)
      // let ch = (e & f) ^ (~e & g);
      let ch = xorStr32(andStr32(e, f), andStr32(notStr32(e), g));

      // Temp1 = h + Σ1 + Choice + Ki + Wi
      // let temp1 = h + s_1 + ch + k[i] + w[i];
      let ad1 = addition32bit(h, s_1)
      let ad2 = addition32bit(ad1, ch)
      let ad3 = addition32bit(ad2, k[i])
      let temp1 = addition32bit(ad3, w[i])

      // Σ0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
      // let s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
      let s_0 = xorStr32(xorStr32(rightrotate(a, 2), rightrotate(a, 13)), rightrotate(a, 22));

      // Majority = (a and b) xor (a and c) xor (b and c)
      // let maj = (a & b) ^ (a & c) ^ (b & c);
      let maj = xorStr32(xorStr32(andStr32(a, b), andStr32(a, c)), andStr32(b, c));

      // Temp2 = Σ0 + Majority
      let temp2 = addition32bit(s_0, maj);

      h = g;
      g = f;
      f = e;
      e = addition32bit(d, temp1);
      d = c;
      c = b;
      b = a;
      a = addition32bit(temp1, temp2);
    }

    // 为下个消息块计算中间哈希值保存其初始值
    h0 = addition32bit(h0, a);
    h1 = addition32bit(h1, b);
    h2 = addition32bit(h2, c);
    h3 = addition32bit(h3, d);
    h4 = addition32bit(h4, e);
    h5 = addition32bit(h5, f);
    h6 = addition32bit(h6, g);
    h7 = addition32bit(h7, h);
  }

  let sha256text = h0.toString(16) + h1.toString(16) + h2.toString(16) + h3.toString(16) + h4.toString(16) + h5.toString(16) + h6.toString(16) + h7.toString(16);

  return sha256text;
}

console.log(SHA256(123));