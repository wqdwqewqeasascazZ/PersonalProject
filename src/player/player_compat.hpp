#pragma once
#include "../player/player.hpp"
#include <enet/enet.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace packet { struct GameUpdatePacket; } // forward-declare only

namespace player::compat {

using byte_vec = std::vector<std::byte>;

// Send a NET_MESSAGE_* + payload (e.g., NET_MESSAGE_GAME_MESSAGE)
int send_packet(player::Player* p,
                std::uint32_t net_message_type,
                const std::string& payload,
                int channel = 0);

// Clone and send a raw ENetPacket
int send_packet_packet(player::Player* p,
                       const ENetPacket* src_packet,
                       int channel = 0);

// Send a NET_MESSAGE_GAME_PACKET with a GameUpdatePacket header (+ optional ext data)
int send_raw_packet(player::Player* p,
                    std::uint32_t net_message_type,
                    const packet::GameUpdatePacket& game_update_packet,
                    const std::uint8_t* ext_data = nullptr,
                    std::size_t ext_len = 0,
                    enet_uint32 flags = ENET_PACKET_FLAG_RELIABLE,
                    int channel = 0);

// Convenience: log via generic text message
int send_log(player::Player* p,
             const std::string& log,
             bool on_console_message = false,
             int channel = 0);

} // namespace player::compat
