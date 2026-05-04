# SMBParser

C++14 静态库，用于解析 SMB 协议（Server Message Block），同时支持 **SMBv1** 和 **SMBv2（2.0 ~ 3.1.1）**。输入 TCP 流数据，输出结构化 JSON 元数据和重组文件。

## 特性

- **双协议支持** — SMBv1（100+ 命令）和 SMBv2 全版本（2.0/2.1/3.0/3.02/3.1.1）
- **传输层自动探测** — NetBIOS Session（port 139）+ Direct TCP（port 445）
- **TCP 分段重组** — feed 追加式接口，自动缓存等待不完整数据
- **容错解析** — 损坏数据自动跳过，通过 magic 扫描恢复同步
- **文件重组** — 跨消息追踪 TreeConnect → Create → Read → Close，聚合文件碎片
- **SMBv2 复合请求** — 自动解析 `next_command` 链
- **JSON 输出** — 聚合数组和 JSON Lines 两种格式
- **跨平台** — MSVC 2022 / GCC / Clang

## 快速上手

### 构建

```bash
cmake -B build -S .
cmake --build build
```

依赖通过 CMake FetchContent 自动下载：
- [nlohmann/json](https://github.com/nlohmann/json) v3.11.3
- [GoogleTest](https://github.com/google/googletest) v1.14.0（仅测试）

### 运行测试

```bash
cmake -B build -S . -DBUILD_TESTING=ON
cmake --build build
./build/tests/Release/smbparser_tests   # Linux
.\build\tests\Release\smbparser_tests.exe  # Windows
```

### 基本使用

```cpp
#include <smbparser/smb_parser.h>
#include <smbparser/file_assembler.h>

smbparser::SMBParser parser;
smbparser::FileAssembler assembler;

// 逐段喂入 TCP 流数据（支持分包）
while (auto segment = next_tcp_segment()) {
    parser.feed(segment.data, segment.len);
}
parser.flush();

// 将解析到的消息送入 FileAssembler 重组文件
for (size_t i = 0; i < parser.messageCount(); i++) {
    if (auto* v1 = parser.getV1Message(i))
        assembler.processV1Message(*v1);
    else if (auto* v2 = parser.getV2Message(i))
        assembler.processV2Message(*v2);
}

// 输出所有消息的 JSON 元数据
std::cout << parser.toJson().dump(2) << std::endl;

// 输出重组文件信息
std::cout << assembler.toJson().dump(2) << std::endl;

// 写出文件到磁盘
for (auto& [key, info] : assembler.files()) {
    std::string name = info.filename.empty()
        ? "unknown_" + key + ".bin"
        : info.filename;
    write_file(name, info.data.data(), info.data.size());
}
```

## 架构

```
  TCP 流数据
      │
      ▼
┌─────────────┐
│  SMBParser   │  ← feed(data, len) 追加式输入
│              │    自动探测 NetBIOS / DirectTCP
│              │    分段重组 + 错误恢复
└──┬───────┬──┘
   │       │
   ▼       ▼
┌──────┐ ┌──────┐
│SMBv1 │ │SMBv2 │  ← 单条消息解析
│Packet│ │Packet│     reinterpret_cast 读固定头
│      │ │      │     validated offset 读变长字段
└──┬───┘ └──┬───┘     toJson() → nlohmann::json
   │        │
   ▼        ▼
┌──────────────┐
│FileAssembler │  ← 跨消息状态追踪
│              │    TreeConnect → Create → Read → Close
│              │    按 TreeID+FileID 聚合碎片
└──────────────┘
```

## 项目结构

```
SMBParser/
├── CMakeLists.txt              # 构建配置
├── include/smbparser/
│   ├── types.h                 # 字节序、packed 宏、SMB 枚举
│   ├── smb1_structs.h          # SMBv1 全部 packed struct
│   ├── smb2_structs.h          # SMBv2 全部 packed struct
│   ├── stream_reader.h         # 边界检查缓冲区读取器
│   ├── smb1_packet.h           # SMBv1Packet 类
│   ├── smb2_packet.h           # SMBv2Packet 类
│   ├── smb_parser.h            # SMBParser 类
│   └── file_assembler.h        # FileAssembler 类
├── src/                        # 实现文件
├── tests/                      # 45 个单元测试 + 集成测试
└── docs/superpowers/           # 设计规范 + 实现计划
```

## API 概览

### SMBParser — TCP 流解析器

```cpp
class SMBParser {
    size_t feed(const uint8_t* data, size_t length);  // 喂入数据，返回新解析消息数
    void flush();                                      // 强制处理缓冲区剩余数据

    size_t messageCount() const;      // 已解析消息总数
    size_t errorCount() const;        // 错误计数
    Transport transport() const;      // 传输类型: NetBIOS / DirectTCP

    const SMBv1Packet* getV1Message(size_t index) const;
    const SMBv2Packet* getV2Message(size_t index) const;

    nlohmann::json toJson() const;    // 聚合 JSON 数组
    std::string toJsonLines() const;  // JSON Lines 格式
};
```

### SMBv1Packet / SMBv2Packet — 单条消息

```cpp
class SMBv2Packet {
    bool isValid() const;              // 消息是否有效
    const std::string& errorMessage() const;

    const Smb2Header* header() const;  // reinterpret_cast 零拷贝
    uint16_t command() const;
    uint32_t status() const;
    uint64_t messageId() const;
    uint64_t sessionId() const;
    uint32_t treeId() const;

    bool hasNextCommand() const;       // SMBv2 复合请求
    size_t nextCommandOffset() const;

    nlohmann::json toJson() const;
};
```

### FileAssembler — 文件重组

```cpp
struct FileInfo {
    std::vector<uint8_t> data;   // 文件内容
    std::string filename;        // 文件名（可能为空）
    std::string share_path;      // 共享路径
    uint64_t file_size;          // 预期大小
    uint64_t bytes_read;         // 实际字节数
    bool is_complete;            // 是否已 Close
};

class FileAssembler {
    void processV1Message(const SMBv1Packet& pkt);
    void processV2Message(const SMBv2Packet& pkt);

    const std::map<std::string, FileInfo>& files() const;
    nlohmann::json toJson() const;
};
```

## 限制

| 项目 | 状态 |
|------|------|
| SMB 签名验证 | 不实现 |
| SMB 加密解密 | 不实现（标记后跳过） |
| 多线程 | 不支持（单线程设计） |
| SMB over UDP | 不支持（仅 TCP） |
| 主动发送 SMB 请求 | 不支持（仅解析） |

## 许可

MIT
