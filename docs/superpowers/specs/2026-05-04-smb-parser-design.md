# SMBParser 库设计规范

> 创建日期: 2026-05-04
> 状态: 已批准

## 1. 概述

SMBParser 是一个 C++14 静态库，用于解析 SMB 协议（Server Message Block），同时支持 **SMBv1** 和 **SMBv2（2.0 ~ 3.1.1）**。输入为已重组排序的 TCP 流数据（可能包含误码和零填充），输出为结构化 JSON 元数据和重组文件。

目标平台：**Windows (MSVC 2022) + Linux (GCC/Clang)**。

---

## 2. 需求摘要

| 需求 | 决策 |
|------|------|
| SMBv1 命令覆盖 | 全部标准命令（100+） |
| SMBv2 版本覆盖 | 2.0, 2.1, 3.0, 3.02, 3.1.1 |
| 传输层 | NetBIOS (port 139) + Direct TCP (port 445) 自动探测 |
| C++ 标准 | C++14 |
| nlohmann::json | CMake FetchContent 集成 |
| 线程安全 | 不需要（单线程） |
| 加密流量 | 不支持，遇加密包标记后跳过 |
| 错误处理 | 记录错误 + 跳过损坏字节 + magic 扫描恢复 |
| 文件提取 | 提取全部文件，缺失元数据时容错聚合 |
| JSON 输出 | 同时支持聚合数组和 JSON Lines 两种格式 |
| 测试框架 | GoogleTest (FetchContent) |
| 开发流程 | Superpowers TDD 流程 |

---

## 3. 架构方案

采用 **混合方案**：固定大小头部使用 `packed struct + reinterpret_cast` 零拷贝访问，变长字段（字符串、数据块）通过 validated offset 访问。

```
┌──────────────────────────────────────────────────┐
│                     SMBParser                     │
│  feed(data, len)  ─→  内部 buffer 管理           │
│  自动检测 NetBIOS / Direct TCP                   │
│  分段重组 + 错误恢复 (magic 扫描)                │
└────────────┬─────────────────┬───────────────────┘
             │                 │
    ┌────────▼────────┐ ┌──────▼─────────┐
    │  SMBv1Packet     │ │  SMBv2Packet    │
    │  ┌────────────┐  │ │  ┌────────────┐  │
    │  │ Header*     │  │ │  │ Header*     │  │  ← reinterpret_cast
    │  │ Param*      │  │ │  │ buffer ref  │  │
    │  │ Data*       │  │ │  │ offsets map │  │  ← validated access
    │  └────────────┘  │ │  └────────────┘  │
    │  toJson() → JSON │ │  toJson() → JSON │
    └────────┬────────┘ └──────┬──────────┘
             │                 │
    ┌────────▼─────────────────▼──────────┐
    │           FileAssembler              │
    │  追踪 TreeConnect/Create/Read/Close │
    │  按 TreeID+FileID 聚合碎片          │
    │  getFiles() → map<id, vector<u8>>   │
    └─────────────────────────────────────┘
```

---

## 4. 项目目录结构

```
SMBParser/
├── CMakeLists.txt              # 顶层：FetchContent nlohmann::json + GoogleTest
├── include/
│   └── smbparser/
│       ├── types.h             # 基础类型：字节序宏、enum、常量
│       ├── smb1_structs.h      # SMBv1 所有命令的 packed struct
│       ├── smb2_structs.h      # SMBv2 所有命令的 packed struct
│       ├── smb1_packet.h       # SMBv1Packet 类声明
│       ├── smb2_packet.h       # SMBv2Packet 类声明
│       ├── smb_parser.h        # SMBParser 类声明
│       ├── file_assembler.h    # FileAssembler 类声明
│       └── stream_reader.h     # 辅助：缓冲区管理 + validated read
├── src/
│   ├── CMakeLists.txt
│   ├── smb1_packet.cpp
│   ├── smb2_packet.cpp
│   ├── smb_parser.cpp
│   ├── file_assembler.cpp
│   └── stream_reader.cpp
└── tests/
    ├── CMakeLists.txt
    ├── test_smb1_structs.cpp
    ├── test_smb2_structs.cpp
    ├── test_stream_reader.cpp
    ├── test_smb1_packet.cpp
    ├── test_smb2_packet.cpp
    ├── test_parser.cpp
    ├── test_file_assembler.cpp
    └── test_error_recovery.cpp
```

模块依赖关系（自底向上）：

```
types.h, smb1_structs.h, smb2_structs.h  ← 全模块共享
    ↓
stream_reader  ← 底层：buffer 管理、validated read
    ↓
smb1_packet, smb2_packet  ← 单消息解析
    ↓
smb_parser  ← 中间层：流入口、分段重组、错误恢复
    ↓
file_assembler  ← 上层：跨消息文件追踪
```

---

## 5. 数据结构设计

### 5.1 基础类型 (types.h)

```cpp
// 跨平台 packed 结构宏
#if defined(_MSC_VER)
#  define PACKED_STRUCT_BEGIN __pragma(pack(push, 1))
#  define PACKED_STRUCT_END   __pragma(pack(pop))
#elif defined(__GNUC__) || defined(__clang__)
#  define PACKED_STRUCT_BEGIN _Pragma("pack(push, 1)")
#  define PACKED_STRUCT_END   _Pragma("pack(pop)")
#endif

// 字节序检测
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define SMB_BIG_ENDIAN 1
#else
#  define SMB_BIG_ENDIAN 0
#endif

// LE ↔ Host 转换（小端平台零开销）
inline uint16_t le16toh(uint16_t v) { /* 大端时 swap */ }
inline uint32_t le32toh(uint32_t v) { /* ... */ }
inline uint64_t le64toh(uint64_t v) { /* ... */ }
inline uint16_t htole16(uint16_t v) { /* ... */ }
```

### 5.2 SMBv1 核心结构

```cpp
PACKED_STRUCT_BEGIN

// SMBv1 通用头 (32 bytes)
struct Smb1Header {
    uint8_t  protocol[4];    // \xFFSMB
    uint8_t  command;        // SMB_COM_xxx
    uint32_t status;         // NTSTATUS
    uint8_t  flags;
    uint16_t flags2;
    uint16_t pid_high;
    uint8_t  signature[8];
    uint16_t reserved;
    uint16_t tid;            // Tree ID
    uint16_t pid_low;
    uint16_t uid;            // User ID
    uint16_t mid;            // Multiplex ID
};

// 所有命令的 Param Block 和 Data Block 按协议规范定义
// 示例: NEGOTIATE response
struct Smb1NegotiateResponse {
    uint8_t  word_count;
    uint16_t dialect_index;
    uint8_t  security_mode;
    uint16_t max_mpx_count;
    uint16_t max_vc_count;
    uint32_t max_buffer_size;
    uint32_t max_raw_size;
    uint32_t session_key;
    uint32_t capabilities;
    uint32_t system_time_low;
    uint32_t system_time_high;
    uint16_t server_timezone;
    uint8_t  challenge_len;
    // 变长字段通过 offset 访问
};

PACKED_STRUCT_END
```

### 5.3 SMBv2 核心结构

```cpp
PACKED_STRUCT_BEGIN

// SMBv2 通用头 (64 bytes)
struct Smb2Header {
    uint8_t  protocol[4];       // \xFESMB
    uint16_t structure_size;    // 固定: 64
    uint16_t credit_charge;
    uint32_t status;
    uint16_t command;           // SMB2_xxx
    uint16_t credit_request;
    uint32_t flags;
    uint32_t next_command;      // 0 或复合请求偏移
    uint64_t message_id;
    uint32_t reserved;
    uint32_t tree_id;
    uint64_t session_id;
    uint8_t  signature[16];
};

// 所有 SMBv2 命令的响应/请求结构
// 示例: NEGOTIATE response
struct Smb2NegotiateResponse {
    uint16_t structure_size;
    uint16_t security_mode;
    uint16_t dialect_revision;
    uint16_t negotiate_context_count;
    uint8_t  server_guid[16];
    uint32_t capabilities;
    uint32_t max_transact_size;
    uint32_t max_read_size;
    uint32_t max_write_size;
    uint64_t system_time;
    uint64_t server_start_time;
    uint16_t security_buffer_offset;
    uint16_t security_buffer_length;
    uint32_t negotiate_context_offset;
    // 变长: security_buffer + negotiate_contexts
};

PACKED_STRUCT_END
```

### 5.4 设计原则

- **固定头 = packed struct**：直接 reinterpret_cast，零拷贝
- **变长字段 = offset + length**：结构体中存储偏移量，解析时做边界检查
- **所有数值字段小端存储**：通过 `le16toh()` / `le32toh()` / `le64toh()` 转换
- **enum class** 映射命令码和状态码，提供 `to_string()` 用于 JSON 输出
- **静态断言**：`static_assert(sizeof(Struct) == expected, "...")` 校验结构体大小
- **SMBv2 复合请求**：通过 `next_command` 字段链式解析

---

## 6. 核心类设计

### 6.1 SMBv1Packet

```cpp
class SMBv1Packet {
public:
    explicit SMBv1Packet(const uint8_t* data, size_t length);

    bool isValid() const;
    const std::string& errorMessage() const;

    const Smb1Header* header() const;
    uint8_t  command() const;
    uint32_t status() const;
    const void* paramBlock() const;
    const uint8_t* dataBlock() const;
    size_t dataBlockSize() const;

    nlohmann::json toJson() const;

private:
    const uint8_t* m_data;       // 非拥有指针
    size_t      m_length;
    bool        m_valid;
    std::string m_error;
    size_t      m_param_offset;
    size_t      m_data_offset;
    size_t      m_data_size;
};
```

**构造验证流程**：
1. 最小长度检查（≥ sizeof(Smb1Header)）
2. Magic 验证：`0xFF "SMB"`
3. WordCount/ByteCount 一致性检查
4. 记录偏移量，标记 valid = true

### 6.2 SMBv2Packet

```cpp
class SMBv2Packet {
public:
    explicit SMBv2Packet(const uint8_t* data, size_t length);

    bool isValid() const;
    const std::string& errorMessage() const;

    const Smb2Header* header() const;
    uint16_t command() const;
    uint32_t status() const;
    uint64_t messageId() const;
    uint64_t sessionId() const;
    uint32_t treeId() const;

    const void* commandParams() const;
    size_t commandParamsSize() const;
    bool hasNextCommand() const;
    size_t nextCommandOffset() const;

    nlohmann::json toJson() const;

private:
    const uint8_t* m_data;
    size_t      m_length;
    bool        m_valid;
    std::string m_error;
};
```

**构造验证流程**：
1. 最小长度检查（≥ sizeof(Smb2Header)）
2. Magic 验证：`0xFE "SMB"`
3. structure_size 验证（固定 64）
4. 命令参数块边界检查

### 6.3 SMBParser

```cpp
enum class Transport { Unknown, NetBIOS, DirectTCP };

class SMBParser {
public:
    SMBParser();

    size_t feed(const uint8_t* data, size_t length);
    void flush();

    size_t messageCount() const;
    size_t errorCount() const;
    Transport transport() const;

    const SMBv1Packet* getV1Message(size_t index) const;
    const SMBv2Packet* getV2Message(size_t index) const;

    nlohmann::json toJson() const;
    std::string toJsonLines() const;

private:
    std::vector<uint8_t>   m_buffer;
    Transport              m_transport = Transport::Unknown;
    std::vector<SMBv1Packet> m_v1_messages;
    std::vector<SMBv2Packet> m_v2_messages;
    size_t                 m_errors = 0;

    bool detectTransport(const uint8_t* data, size_t len);
    void processBuffer();
    bool tryParseNetBIOS();
    bool tryParseDirectTCP();
    bool tryParseV1(const uint8_t* data, size_t len);
    bool tryParseV2(const uint8_t* data, size_t len);
    void handleError(const uint8_t* data, size_t len);
    void consumeFromBuffer(size_t bytes);
};
```

**解析流程**：

```
feed(data, len)
  │
  ├─ 1. 追加到 m_buffer
  ├─ 2. detectTransport()（仅首次）
  │     NetBIOS: 前 4 字节 = 长度 (bit 23=0, ≤0x1FFFF)
  │     DirectTCP: 前 4 字节 = \xFF"SMB" 或 \xFE"SMB"
  └─ 3. processBuffer() 循环解析
        ├─ NetBIOS 模式: 读 4 字节长度 → 等待完整消息 → tryParseV1/V2
        ├─ DirectTCP 模式: 检查 magic → tryParseV1/V2
        ├─ 成功 → 存入 m_v1/v2_messages → consume
        └─ 失败 → handleError() → 扫描下一个 magic
```

**错误恢复**：
```
handleError():
  1. m_errors++
  2. 从当前位置 +1 开始扫描 \xFF"SMB" 或 \xFE"SMB"
  3. 找到 → consumeFromBuffer(i)，跳过损坏字节
  4. 未找到 → 清空 m_buffer（无法恢复）
```

### 6.4 FileAssembler

```cpp
struct FileInfo {
    std::vector<uint8_t> data;
    std::string filename;       // 可能为空
    std::string share_path;
    uint64_t  file_size = 0;
    uint64_t  bytes_read = 0;
    bool      is_complete = false;
    uint32_t  tree_id = 0;
    std::string file_id_hex;
    uint16_t  fid = 0;
};

class FileAssembler {
public:
    void processV1Message(const SMBv1Packet& pkt);
    void processV2Message(const SMBv2Packet& pkt);

    const std::map<std::string, FileInfo>& files() const;
    nlohmann::json toJson() const;

private:
    std::map<uint32_t, std::string>        m_tree_map;      // TreeID → path
    std::map<uint32_t, std::string>        m_fid_filename;  // SMBv1 FID → name
    std::map<std::string, std::string>     m_fileid_filename;// SMBv2 FileID → name
    std::map<std::string, FileInfo>        m_files;         // key → 文件

    std::string makeFileKey(uint32_t tree_id, uint16_t fid);
    std::string makeFileKeyV2(uint32_t tree_id, const std::string& file_id);
    void appendData(const std::string& key, const uint8_t* data, size_t len);
};
```

**状态追踪**：

| 消息类型 | 动作 | 状态变化 |
|---------|------|---------|
| TREE_CONNECT | 记录 share_path | `m_tree_map[tid] = path` |
| NT_CREATE / SMB2_CREATE | 记录 filename, 创建入口 | `m_files[key] = FileInfo{...}` |
| READ / SMB2_READ | 追加数据 | `m_files[key].data += chunk` |
| WRITE / SMB2_WRITE | 追加数据 | 同上 |
| CLOSE / SMB2_CLOSE | 标记完成 | `m_files[key].is_complete = true` |

**容错策略**：
- 无 TreeConnect → share_path 留空，仍追踪文件数据
- 无 Create → 生成匿名 key `"unknown_{tid}_{fid}"`，仍聚合
- 无 Close → `is_complete = false`，但数据仍输出
- 文件名缺失 → filename 为 null/空字符串

### 6.5 StreamReader

```cpp
class StreamReader {
public:
    StreamReader(const uint8_t* data, size_t length);

    template<typename T>
    bool read(size_t offset, T& out) const;

    bool readString(size_t offset, size_t max_len,
                    std::string& out, bool is_unicode = false) const;
    bool readBytes(size_t offset, size_t len,
                   const uint8_t*& out) const;

    size_t length() const;
    bool canRead(size_t offset, size_t size) const;

private:
    const uint8_t* m_data;
    size_t m_length;
};
```

所有 validated read 集中在此类中，任何越界访问返回 false。

---

## 7. JSON 输出格式

### 7.1 SMBv1Packet / SMBv2Packet toJson()

```json
{
  "protocol": "SMBv2",
  "dialect": "2.1",
  "command": "SMB2_READ",
  "command_code": 8,
  "status": "STATUS_SUCCESS",
  "message_id": 42,
  "session_id": "0x0000000000000001",
  "tree_id": "0x00000001",
  "params": {
    "length": 65536,
    "offset": 0,
    "file_id": "0xFFFFFFFF00000001",
    "min_bytes": 0,
    "channel": 0,
    "remaining_bytes": 0
  },
  "data_offset": 136,
  "data_size": 65536,
  "has_next": false
}
```

无效消息：
```json
{
  "protocol": "SMBv1",
  "valid": false,
  "error": "bad SMBv1 magic",
  "raw_offset": 1024,
  "raw_size": 200
}
```

### 7.2 FileAssembler toJson()

```json
{
  "files": [
    {
      "filename": "secret.docx",
      "share_path": "\\\\SERVER\\Share",
      "file_size": 245760,
      "bytes_read": 245760,
      "is_complete": true,
      "tree_id": "0x0001",
      "file_id": "0xFFFFFFFF00000001",
      "protocol": "SMBv2",
      "data_size": 245760
    },
    {
      "filename": null,
      "share_path": "\\\\SERVER\\IPC$",
      "file_size": 0,
      "bytes_read": 1048576,
      "is_complete": false,
      "note": "filename unknown, stream incomplete"
    }
  ]
}
```

---

## 8. 编译配置

```cmake
cmake_minimum_required(VERSION 3.14)
project(SMBParser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FetchContent: nlohmann::json
include(FetchContent)
FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3)
FetchContent_MakeAvailable(json)

# 静态库
add_library(smbparser STATIC
    src/stream_reader.cpp
    src/smb1_packet.cpp
    src/smb2_packet.cpp
    src/smb_parser.cpp
    src/file_assembler.cpp)
target_include_directories(smbparser PUBLIC include)
target_link_libraries(smbparser PUBLIC nlohmann_json::nlohmann_json)

# 测试（可选，通过 BUILD_TESTING 控制）
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    add_subdirectory(tests)
endif()
```

---

## 9. 测试策略

| 层级 | 测试对象 | 验证点 |
|------|---------|--------|
| L1 | 数据结构 | `static_assert(sizeof(struct))`, 对齐一致性, 字节序转换 |
| L2 | StreamReader | 正常读取, 越界返回 false, Unicode/ASCII 字符串解析 |
| L3 | SMBv1Packet / SMBv2Packet | 正常解析 → valid, 损坏包 → invalid + error, toJson 格式, SMBv2 复合请求 |
| L4 | SMBParser | NetBIOS/DirectTCP 分段喂入, 跨 feed 分包等待, 损坏恢复, 传输探测 |
| L5 | FileAssembler | 完整链路追踪, 多文件不混淆, 缺失元数据容错, 无 Close 处理 |

测试数据来源：
- 手工构造字节数组（精确控制）
- Wireshark 真实 pcap 提取
- 损坏数据注入（误码/零填充）

---

## 10. 约束与排除

| 项目 | 状态 |
|------|------|
| SMB 签名验证 | 不实现（读取但不验证） |
| SMB 加密解密 | 不实现（标记 encrypted 后跳过） |
| 多线程 | 不支持（单线程设计） |
| SMB over NetBIOS over UDP | 不支持（仅 TCP） |
| 主动发送 SMB 请求 | 不支持（仅解析） |
| SMBv1 事务子协议（TRANSACT2, NT_TRANSACT） | 基础支持（解析参数头，不深入子协议） |

---

## 11. 后续阶段

1. `writing-plans` → 详细实现计划（任务拆分、优先级、依赖）
2. 按计划 TDD 实现（测试先行 → 代码 → 重构）
3. `requesting-code-review` → 每个里程碑审查
4. `verification-before-completion` → 最终验证
