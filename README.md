# SMBParser

C++14 静态库，用于解析 SMB 协议（Server Message Block），同时支持 **SMBv1** 和 **SMBv2（2.0 ~ 3.1.1）**。输入 TCP 流数据，输出结构化 JSON 元数据和重组文件。

## 特性

- **双协议支持** — SMBv1（100+ 命令）和 SMBv2 全版本（2.0/2.1/3.0/3.02/3.1.1）
- **传输层自动探测** — NetBIOS Session（port 139）+ Direct TCP（port 445）
- **TCP 分段重组** — `feed()` 追加式接口，自动缓存等待不完整数据
- **容错解析** — 损坏数据自动跳过，通过 magic 字节扫描恢复同步
- **文件重组** — 跨消息追踪 TreeConnect → Create → Read/Write → Close，聚合文件碎片
- **SMBv2 复合请求** — 自动解析 `next_command` 链
- **JSON 输出** — 聚合数组和 JSON Lines 两种格式
- **跨平台** — MSVC 2022 / GCC / Clang

## 构建

```bash
cmake -B build -S .
cmake --build build
```

依赖通过 CMake `FetchContent` 自动下载（首次配置需网络，约 20MB）：

| 库 | 版本 | 用途 |
|----|------|------|
| [nlohmann/json](https://github.com/nlohmann/json) | v3.11.3 | JSON 输出 |
| [GoogleTest](https://github.com/google/googletest) | v1.14.0 | 单元测试 |

### 可选：构建并运行测试

```bash
cmake -B build -S . -DBUILD_TESTING=ON
cmake --build build
./build/tests/Release/smbparser_tests       # Linux
.\build\tests\Release\smbparser_tests.exe    # Windows
```

### 集成到你的 CMake 项目

```cmake
# 方式 1: FetchContent
include(FetchContent)
FetchContent_Declare(smbparser
    GIT_REPOSITORY https://github.com/your-org/SMBParser.git
    GIT_TAG main)
FetchContent_MakeAvailable(smbparser)
target_link_libraries(your_app PRIVATE smbparser)

# 方式 2: 已安装的库
find_package(smbparser REQUIRED)
target_link_libraries(your_app PRIVATE smbparser)
```

## 快速使用

### 场景 1：解析 TCP 流并输出所有消息的 JSON

```cpp
#include <smbparser/smb_parser.h>

smbparser::SMBParser parser;

// 逐段喂入（支持分包）
parser.feed(segment1_data, segment1_len);
parser.feed(segment2_data, segment2_len);
parser.flush();

// 输出所有消息
std::cout << parser.toJson().dump(2) << std::endl;
// 或每行一条 JSON
std::cout << parser.toJsonLines();
```

### 场景 2：解析消息并重组传输的文件

```cpp
#include <smbparser/smb_parser.h>
#include <smbparser/file_assembler.h>

smbparser::SMBParser parser;
smbparser::FileAssembler assembler;

parser.feed(tcp_data, len);
parser.flush();

// 将所有消息送入 FileAssembler
for (size_t i = 0; i < parser.messageCount(); i++) {
    if (auto* v1 = parser.getV1Message(i))
        assembler.processV1Message(*v1);
    else if (auto* v2 = parser.getV2Message(i))
        assembler.processV2Message(*v2);
}

// 查看重组结果
for (const auto& [key, info] : assembler.files()) {
    std::cout << "File: " << (info.filename.empty() ? "(unknown)" : info.filename) << "\n";
    std::cout << "  Share:  " << info.share_path << "\n";
    std::cout << "  Size:   " << info.file_size << " (got " << info.bytes_read << ")\n";
    std::cout << "  Done:   " << (info.is_complete ? "yes" : "partial") << "\n";
    // info.data 中是文件的实际内容
}
```

### 场景 3：仅解析消息，按命令过滤

```cpp
smbparser::SMBParser parser;
parser.feed(data, len);
parser.flush();

for (size_t i = 0; i < parser.messageCount(); i++) {
    if (auto* pkt = parser.getV2Message(i)) {
        switch (pkt->command()) {
        case smbparser::SMB2_CREATE: {
            auto j = pkt->toJson();
            std::cout << "CREATE: file_id="
                      << j["params"]["file_id"] << "\n";
            break;
        }
        case smbparser::SMB2_READ:
            std::cout << "READ: session=" << pkt->sessionId() << "\n";
            break;
        }
    }
}
```

### 场景 4：边喂入边组装文件（低内存）

```cpp
smbparser::SMBParser parser;
smbparser::FileAssembler assembler;
size_t last_count = 0;

for (auto& segment : tcp_segments) {
    size_t new_msgs = parser.feed(segment.data, segment.len);

    // 仅处理新消息，避免重复遍历
    for (size_t i = last_count; i < parser.messageCount(); i++) {
        if (auto* pkt = parser.getV2Message(i))
            assembler.processV2Message(*pkt);
    }
    last_count = parser.messageCount();
}
parser.flush(); // 处理残留
```

## JSON 输出格式

### 单条消息 toJson()

```json
{
  "protocol": "SMBv2",
  "valid": true,
  "command": "SMB2_READ",
  "command_code": 8,
  "status": "STATUS_SUCCESS",
  "message_id": 42,
  "session_id": 604404383318016,
  "tree_id": 1,
  "credit_request": 128,
  "flags": 0,
  "has_next": false,
  "params": {
    "data_length": 65536,
    "data_offset": 17,
    "data_remaining": 0
  }
}
```

无效消息：
```json
{
  "protocol": "SMBv1",
  "valid": false,
  "error": "bad SMBv1 magic"
}
```

### 文件重组 toJson()

```json
{
  "files": [
    {
      "filename": "report.docx",
      "share_path": "\\\\192.168.1.100\\Share",
      "file_size": 245760,
      "bytes_read": 245760,
      "is_complete": true,
      "tree_id": 1,
      "file_id": "FFFFFFFF00000001",
      "protocol": "SMBv2",
      "data_size": 245760
    },
    {
      "filename": null,
      "share_path": null,
      "file_size": 0,
      "bytes_read": 1048576,
      "is_complete": false,
      "note": "filename unknown, stream incomplete"
    }
  ]
}
```

## API 参考

### SMBParser — TCP 流解析器

```cpp
namespace smbparser {

enum class Transport { Unknown, NetBIOS, DirectTCP };

class SMBParser {
public:
    // 主入口：喂入 TCP 流数据（任意分段大小），返回本次新解析的消息数
    size_t feed(const uint8_t* data, size_t length);

    // 强制处理缓冲区中剩余数据
    void flush();

    // 已解析消息总数
    size_t messageCount() const;

    // 跳过/损坏的消息数
    size_t errorCount() const;

    // 自动探测到的传输类型
    Transport transport() const;

    // 按索引访问解析结果，未找到返回 nullptr
    const SMBv1Packet* getV1Message(size_t index) const;
    const SMBv2Packet* getV2Message(size_t index) const;

    // 序列化所有消息为 JSON（聚合数组）
    nlohmann::json toJson() const;

    // JSON Lines 格式（每行一条消息）
    std::string toJsonLines() const;
};
}
```

### SMBv1Packet — SMBv1 单条消息

```cpp
class SMBv1Packet {
public:
    explicit SMBv1Packet(const uint8_t* data, size_t length);

    bool isValid() const;                    // 消息是否通过验证
    const std::string& errorMessage() const; // 验证失败原因

    const Smb1Header* header() const;        // reinterpret_cast，零拷贝
    uint8_t command() const;                 // SMB_COM_xxx
    uint32_t status() const;                 // NTSTATUS

    const void* paramBlock() const;          // WordCount 之后的参数块
    const uint8_t* dataBlock() const;        // ByteCount 之后的数据块
    size_t dataBlockSize() const;            // 数据块大小

    nlohmann::json toJson() const;           // 包含 params 子对象
};
```

### SMBv2Packet — SMBv2 单条消息

```cpp
class SMBv2Packet {
public:
    explicit SMBv2Packet(const uint8_t* data, size_t length);

    bool isValid() const;
    const std::string& errorMessage() const;
    const Smb2Header* header() const;

    uint16_t command() const;          // SMB2_xxx
    uint32_t status() const;           // NTSTATUS
    uint64_t messageId() const;
    uint64_t sessionId() const;
    uint32_t treeId() const;

    const void* commandParams() const; // 命令固定参数块
    size_t commandParamsSize() const;

    bool hasNextCommand() const;       // SMBv2 复合请求
    size_t nextCommandOffset() const;

    nlohmann::json toJson() const;     // 含 params 子对象
};
```

### FileAssembler — 文件重组器

```cpp
struct FileInfo {
    std::vector<uint8_t> data;   // 文件内容
    std::string filename;        // 文件名（可能为空）
    std::string share_path;      // 共享路径（可能为空）
    uint64_t file_size;          // 预期大小（从 Create 响应获取）
    uint64_t bytes_read;         // 实际已读字节数
    bool is_complete;            // 是否已 Close
    uint32_t tree_id;            // Tree Connect ID
    std::string file_id_hex;     // SMBv2 FileId（十六进制）
    uint16_t fid;                // SMBv1 FID
    std::string protocol;        // "SMBv1" 或 "SMBv2"
};

class FileAssembler {
public:
    // 处理一条已解析的消息
    void processV1Message(const SMBv1Packet& pkt);
    void processV2Message(const SMBv2Packet& pkt);

    // 获取所有追踪到的文件（key = "treeId_fileId"）
    const std::map<std::string, FileInfo>& files() const;

    // 序列化为 JSON
    nlohmann::json toJson() const;
};
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

## 限制

| 项目 | 说明 |
|------|------|
| SMB 签名验证 | 不实现 |
| SMB 3.x 加密 | `processV2Message` 入口处检查 `SMB2_FLAGS_ENCRYPTED` 并跳过 |
| 多线程 | 不支持（单线程设计） |
| SMB over UDP | 不支持（仅 TCP） |
| 主动发送请求 | 不支持（仅解析） |

## 许可

MIT
