#pragma once
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <utility>
#include <cstdint>

#include "../player/player.hpp"        // GTProxy v2.0.0 player class
#include "../player/local_player.hpp"  // if present (optional)
#include "../player/remote_player.hpp" // if present (optional)

namespace command {

struct CommandContext {
    std::string name;
    std::vector<std::string> aliases;
    std::string description;
};

struct CommandCallContext {
    std::string prefix;

    // GTProxy v2.0.0 uses player::Player + player::compat helpers
    // These may be null if not available in the current context.
    player::Player* client_player{ nullptr };   // the client connection (was local_peer)
    player::Player* server_player{ nullptr };   // connection to growtopia server (was server_peer)

    // Optional: If your build exposes LocalPlayer / RemotePlayer wrappers
    player::LocalPlayer* local_player{ nullptr };
    std::unordered_map<uint32_t, player::RemotePlayer*> remote_players;
};

class Command {
public:
    Command(CommandContext context,
            std::function<void(const CommandCallContext&, const std::vector<std::string>&)> callback)
        : m_context(std::move(context)), m_callback(std::move(callback)) {}

    ~Command() = default;

    void call(const CommandCallContext& ctx, const std::vector<std::string>& args) {
        m_callback(ctx, args);
    }

    [[nodiscard]] CommandContext get_context() const { return m_context; }
    [[nodiscard]] std::string get_name() const { return m_context.name; }
    [[nodiscard]] std::vector<std::string> get_aliases() const { return m_context.aliases; }
    [[nodiscard]] std::string get_description() const { return m_context.description; }

private:
    CommandContext m_context;
    std::function<void(const CommandCallContext&, const std::vector<std::string>&)> m_callback;
};

} // namespace command
