#include "player_compat.hpp"
#include "../packet/packet_types.hpp"
#include <cstring>
#include <fmt/format.h>

namespace player::compat {

using byte_vec = std::vector<std::byte>;

static byte_vec build_net_message_uint32(std::uint32_t net_message_type,
                                         const std::string& payload)
{
    byte_vec out;
    out.resize(sizeof(std::uint32_t) + payload.size());
    std::memcpy(out.data(), &net_message_type, sizeof(std::uint32_t));
    if (!payload.empty())
        std::memcpy(out.data() + sizeof(std::uint32_t), payload.data(), payload.size());
    return out;
}

static byte_vec build_game_packet_uint32(std::uint32_t net_message_type,
                                         const packet::GameUpdatePacket& g,
                                         const std::uint8_t* ext,
                                         std::size_t ext_len)
{
    const std::size_t total = sizeof(std::uint32_t) + sizeof(packet::GameUpdatePacket) + ext_len;
    byte_vec out(total);
    std::memcpy(out.data(), &net_message_type, sizeof(std::uint32_t));
    std::memcpy(out.data() + sizeof(std::uint32_t), &g, sizeof(packet::GameUpdatePacket));
    if (ext_len && ext) {
        std::memcpy(out.data() + sizeof(std::uint32_t) + sizeof(packet::GameUpdatePacket), ext, ext_len);
    }
    return out;
}

int send_packet(player::Player* p,
                std::uint32_t net_message_type,
                const std::string& data,
                int channel)
{
    if (!p) return -1;
    auto buf = build_net_message_uint32(net_message_type, data);
    return p->send_packet(buf, channel) ? 0 : -1;
}

int send_packet_packet(player::Player* p,
                       const ENetPacket* src_packet,
                       int channel)
{
    if (!p || !src_packet) return -1;
    byte_vec out(src_packet->dataLength);
    if (src_packet->dataLength)
        std::memcpy(out.data(), src_packet->data, src_packet->dataLength);
    return p->send_packet(out, channel) ? 0 : -1;
}

int send_raw_packet(player::Player* p,
                    std::uint32_t net_message_type,
                    const packet::GameUpdatePacket& game_update_packet,
                    const std::uint8_t* ext_data,
                    std::size_t ext_len,
                    enet_uint32 /*flags*/,
                    int channel)
{
    if (!p) return -1;
    if (ext_len > 0xF4240) return -1; // ~1MB safety cap

    auto buf = build_game_packet_uint32(net_message_type, game_update_packet, ext_data, ext_len);
    return p->send_packet(buf, channel) ? 0 : -1;
}

int send_log(player::Player* p,
             const std::string& log,
             bool /*on_console_message*/,
             int channel)
{
    if (!p) return -1;
    const auto payload = fmt::format("action|log\nmsg|{}", log);
    return send_packet(p,
                       static_cast<std::uint32_t>(packet::NET_MESSAGE_GAME_MESSAGE),
                       payload,
                       channel);
}

} // namespace player::compat
