#include <android/log.h>
#include <thread>
#include <cstring>
#include <fstream>
#include <vector>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <sys/stat.h>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <nlohmann/json.hpp>

#define LOG_TAG "Executor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using json = nlohmann::json;
using websocketpp::connection_hdl;
using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

typedef int (*luaL_loadstring_t)(void* L, const char* s);
typedef int (*lua_pcall_t)(void* L, int nargs, int nresults, int errfunc);

luaL_loadstring_t g_luaL_loadstring = nullptr;
lua_pcall_t g_lua_pcall = nullptr;
void* g_lua_state = nullptr;
std::atomic<bool> g_running(true);
const char* CACHE_PATH = "/data/local/tmp/executor_cache.bin";

struct CacheData {
    uint32_t magic = 0xDEADBEEF;
    uint32_t version = 1;
    uint64_t timestamp = 0;
    uintptr_t addr_loadstring = 0;
    uintptr_t addr_pcall = 0;
    uint32_t checksum = 0;
};

uint32_t calculateChecksum(const void* data, size_t len) {
    uint32_t sum = 0;
    const uint8_t* bytes = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) sum += bytes[i];
    return sum;
}

bool saveCache(const CacheData& cache) {
    std::ofstream ofs(CACHE_PATH, std::ios::binary);
    if (!ofs) return false;
    ofs.write((char*)&cache, sizeof(cache));
    return !ofs.fail();
}

bool loadCache(CacheData& cache) {
    std::ifstream ifs(CACHE_PATH, std::ios::binary);
    if (!ifs) return false;
    ifs.read((char*)&cache, sizeof(cache));
    if (ifs.gcount() != sizeof(cache)) return false;
    if (cache.magic != 0xDEADBEEF || cache.version != 1) return false;
    uint32_t stored_checksum = cache.checksum;
    cache.checksum = 0;
    uint32_t calc = calculateChecksum(&cache, sizeof(cache));
    if (stored_checksum != calc) return false;
    cache.checksum = stored_checksum;
    return true;
}

std::vector<std::pair<uintptr_t, uintptr_t>> getExecutableRegions() {
    std::vector<std::pair<uintptr_t, uintptr_t>> regions;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (perms[0] == 'r' && perms[2] == 'x')
                regions.emplace_back(start, end);
        }
    }
    return regions;
}

uintptr_t findPatternInRange(uintptr_t start, uintptr_t end,
                             const std::vector<uint8_t>& pattern, const char* mask) {
    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) return 0;
    size_t patLen = pattern.size();
    uint8_t buf[4096];
    for (uintptr_t addr = start; addr < end - patLen; addr += 4096) {
        size_t toRead = std::min<size_t>(end - addr, 4096);
        if (pread(fd, buf, toRead, addr) != (ssize_t)toRead) break;
        for (size_t i = 0; i <= toRead - patLen; ++i) {
            bool ok = true;
            for (size_t j = 0; j < patLen; ++j) {
                if (mask[j] == 'x' && buf[i + j] != pattern[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                close(fd);
                return addr + i;
            }
        }
    }
    close(fd);
    return 0;
}

uintptr_t findFunction(const std::vector<uint8_t>& pattern, const char* mask) {
    auto regions = getExecutableRegions();
    for (auto& [start, end] : regions) {
        uintptr_t addr = findPatternInRange(start, end, pattern, mask);
        if (addr != 0) return addr;
    }
    return 0;
}

#if defined(__aarch64__)
static const std::vector<uint8_t> LOADSTRING_SIG = {
    0xff, 0x43, 0x01, 0xd1, 0xfc, 0x0f, 0x00, 0xf9,
    0xf4, 0x4f, 0x02, 0xa9, 0xfd, 0x7b, 0x03, 0xa9
};
static const char* LOADSTRING_MASK = "xxxxxxxxxxxxxxxx";
#elif defined(__arm__)
static const std::vector<uint8_t> LOADSTRING_SIG = {
    0x2d, 0xe9, 0xf0, 0x4f, 0x04, 0xb0, 0x8d, 0xe2, 0x00, 0x60, 0xa0, 0xe1
};
static const char* LOADSTRING_MASK = "xxxxxxxxxxxx";
#endif

bool updateSignatures() {
    LOGI("Auto-dump: scanning memory...");
    uintptr_t addr_ls = findFunction(LOADSTRING_SIG, LOADSTRING_MASK);
    if (addr_ls == 0) {
        LOGE("Auto-dump failed: luaL_loadstring not found");
        return false;
    }
    g_luaL_loadstring = (luaL_loadstring_t)addr_ls;
    LOGI("Found luaL_loadstring at %p", (void*)addr_ls);
    CacheData cache;
    cache.magic = 0xDEADBEEF;
    cache.version = 1;
    cache.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    cache.addr_loadstring = addr_ls;
    cache.checksum = 0;
    cache.checksum = calculateChecksum(&cache, sizeof(cache));
    saveCache(cache);
    return true;
}

void initFunctions() {
    CacheData cache;
    if (loadCache(cache)) {
        time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        if (now - cache.timestamp < 12 * 3600) {
            g_luaL_loadstring = (luaL_loadstring_t)cache.addr_loadstring;
            LOGI("Loaded from cache");
            return;
        }
    }
    updateSignatures();
}

std::string xor_crypt(const std::string& input, char key) {
    std::string out = input;
    for (char& c : out) c ^= key;
    return out;
}

void executeScript(const std::string& encrypted_script) {
    if (!g_luaL_loadstring || !g_lua_state) {
        LOGE("Lua functions or state missing");
        return;
    }
    std::string script = xor_crypt(encrypted_script, 0xAA);
    if (g_luaL_loadstring(g_lua_state, script.c_str()) != 0) {
        LOGE("luaL_loadstring failed");
        return;
    }
    if (g_lua_pcall(g_lua_state, 0, 0, 0) != 0) {
        LOGE("lua_pcall failed");
        return;
    }
    LOGI("Executed: %.50s", script.c_str());
}

typedef websocketpp::server<websocketpp::config::asio> ws_server_t;

void on_message(ws_server_t* srv, connection_hdl hdl, ws_server_t::message_ptr msg) {
    auto json_msg = json::parse(msg->get_payload());
    if (json_msg.contains("action")) {
        std::string action = json_msg["action"];
        if (action == "execute" && json_msg.contains("script")) {
            std::string enc_script = json_msg["script"];
            executeScript(enc_script);
            json reply = {{"status", "executed"}};
            srv->send(hdl, reply.dump(), websocketpp::frame::opcode::text);
        } else if (action == "dump") {
            bool ok = updateSignatures();
            json reply = {{"status", ok ? "dumped" : "failed"}};
            srv->send(hdl, reply.dump(), websocketpp::frame::opcode::text);
        }
    }
}

void wsServerThread() {
    ws_server_t server;
    server.set_message_handler(bind(&on_message, &server, ::_1, ::_2));
    server.init_asio();
    server.listen(8081);
    server.start_accept();
    LOGI("WebSocket server on port 8081");
    server.run();
}

void autoUpdateLoop() {
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::hours(12));
        LOGI("Auto-dump scheduled...");
        updateSignatures();
    }
}

extern "C" void __attribute__((constructor)) init() {
    LOGI("Executor loaded");
    initFunctions();
    std::thread(wsServerThread).detach();
    std::thread(autoUpdateLoop).detach();
}