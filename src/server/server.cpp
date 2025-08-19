#include <magic_enum/magic_enum.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>

#include "server.hpp"
#include "../client/client.hpp"
#include "../packet/packet_types.hpp"
#include "../utils/byte_stream.hpp"
#include "../utils/network.hpp"
#include "../packet/message/chat.hpp"
#include "../utils/packet_utils.hpp"   // added for send_chat_message

#include <cstring> // memcpy
#include <memory>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <fmt/format.h>

namespace server {

// -----------------------------------------------------------------------------
// File-local helpers
// -----------------------------------------------------------------------------

// Build a contiguous byte vector containing the in-memory representation of
// a GameUpdatePacket followed by ext_data bytes. This mirrors how your code
// reads GameUpdatePacket + ext_data using ByteStream::read(game_update_packet)
// followed by read_vector(ext_data, size).
static std::vector<std::byte> build_game_update_bytes(const packet::GameUpdatePacket& pkt,
                                                      const std::vector<std::byte>& ext_data)
{
    size_t header_size = sizeof(packet::GameUpdatePacket);
    size_t total_size = header_size + ext_data.size();

    std::vector<std::byte> out;
    out.resize(total_size);

    // Copy struct bytes first (assumes POD-like layout used by ByteStream::read)
    if (header_size > 0) {
        std::memcpy(out.data(), reinterpret_cast<const void*>(&pkt), header_size);
    }

    // Copy extended data after header
    if (!ext_data.empty()) {
        std::memcpy(out.data() + header_size, ext_data.data(), ext_data.size());
    }

    return out;
}

// Send GameUpdatePacket + ext_data to a given player using Player::send_packet
// Returns true on send_packet success (Player::send_packet return value).
static bool send_game_update_to_player(player::Player* plr,
                                       const packet::GameUpdatePacket& pkt,
                                       const std::vector<std::byte>& ext_data,
                                       int channel = 0)
{
    if (!plr) return false;
    const auto bytes = build_game_update_bytes(pkt, ext_data);
    bool ok = plr->send_packet(bytes, channel);
    spdlog::info("[server] send_game_update_to_player: ok={}, size={}, pkt_type={}",
                 ok, bytes.size(), magic_enum::enum_name(pkt.type));
    return ok;
}

// Convenience: send a plain action/game-message string (e.g. "action|join_request...")
// by turning it into bytes and using Player::send_packet. This mirrors how your
// code forwards text messages using `to_player->send_packet(byte_stream.get_data(), 0);`
static bool send_game_message_string(player::Player* plr, const std::string& message, int channel = 0)
{
    if (!plr) return false;
    std::vector<std::byte> bytes;
    bytes.resize(message.size());
    if (!message.empty()) {
        std::memcpy(bytes.data(), message.data(), message.size());
    }
    bool ok = plr->send_packet(bytes, channel);
    spdlog::info("[server] send_game_message_string: ok={}, size={}, preview='{}'",
                 ok, bytes.size(), (message.size() > 120 ? message.substr(0, 120) + "..." : message));
    return ok;
}

// -----------------------------------------------------------------------------
// Server implementation
// -----------------------------------------------------------------------------

Server::Server(core::Core* core)
    : core_{ core }
    , player_{ nullptr }
{
    ENetAddress address{};
    address.host = ENET_HOST_ANY;
    address.port = core->get_config().get<unsigned int>("server.port");

    host_ = enet_host_create(&address, 1, 2, 0, 0);
    if (!host_) {
        return;
    }

    if (enet_host_compress_with_range_coder(host_) != 0) {
        return;
    }

    host_->checksum = enet_crc32;
    host_->usingNewPacketForServer = 1;

    spdlog::info(
        "The server is up and running with port {} and {} peers can join!",
        host_->address.port,
        host_->peerCount
    );
}

Server::~Server()
{
    enet_host_destroy(host_);
    delete player_;
}

void Server::process()
{
    // Perform server processing here
    if (!host_) {
        return;
    }

    ENetEvent ev{};
    while (enet_host_service(host_, &ev, 16) > 0) {
        switch (ev.type) {
        case ENET_EVENT_TYPE_CONNECT:
            on_connect(ev.peer);
            break;
        case ENET_EVENT_TYPE_DISCONNECT:
            on_disconnect(ev.peer);
            break;
        case ENET_EVENT_TYPE_RECEIVE:
            on_receive(ev.peer, ev.packet);
            break;
        default:
            break;
        }
    }
}

void Server::on_connect(ENetPeer* peer)
{
    spdlog::info(
        "The server just got a new connection from the address {}:{}!",
        network::format_ip_address(peer->address.host),
        peer->address.port
    );

    // GOOD JOB GROWTOPIA TEAM! PLEASE MAKE YOUR CLIENTS HANG LONGER!!!
    enet_peer_timeout(peer, 0, 12000, 0);

    player_ = new player::Player{ peer };

    const core::EventConnection event_connection{ *player_ };
    event_connection.from = core::EventFrom::FromClient;
    core_->get_event_dispatcher().dispatch(event_connection);
}

void Server::on_receive(ENetPeer* peer, ENetPacket* packet)
{
    if (!player_) {
        enet_peer_disconnect(peer, 0);
        return;
    }

    // 'to_player' is the upstream (client) side player that represents the real Growtopia server connection
    const player::Player* to_player{ core_->get_client()->get_player() };
    if (!to_player) {
        player_->disconnect();
        return;
    }

    ByteStream byte_stream{ reinterpret_cast<std::byte*>(packet->data), packet->dataLength };
    if (byte_stream.get_size() < 4 || byte_stream.get_size() > 16384 /* 16kb */) {
        player_->disconnect();
        return;
    }

    enet_packet_destroy(packet);

    packet::NetMessageType type{};
    if (!byte_stream.read(type)) {
        player_->disconnect();
        return;
    }

    if (type == packet::NET_MESSAGE_GENERIC_TEXT || type == packet::NET_MESSAGE_GAME_MESSAGE) {
        std::string message{};
        byte_stream.read(message, byte_stream.get_size() - sizeof(packet::NetMessageType) - 1);

        TextParse text_parse{ message };
        if (core_->get_config().get<bool>("log.printMessage")) {
            spdlog::info("Incoming message from client:");
            for (const auto& key_value : text_parse.get_key_values()) {
                spdlog::info("\t{}", key_value);
            }
        }

        const core::EventMessage event_message{ *player_, *to_player, text_parse };
        event_message.from = core::EventFrom::FromClient;
        core_->get_event_dispatcher().dispatch(event_message);

        // --- NEW: intercept /warp / !warp typed by the client
        std::string text_field = text_parse.get("text");
        auto trim = [](std::string &s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
        };
        trim(text_field);

        if (!text_field.empty()) {
            std::string lower = text_field;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

            if (lower.rfind("/warp", 0) == 0 || lower.rfind("!warp", 0) == 0) {
                std::istringstream iss(text_field);
                std::string cmd; iss >> cmd;
                std::string world; iss >> world;
                trim(world);

                if (world.empty()) {
                    utils::PacketUtils::send_chat_message(player_, "`4Usage: ``/warp <world name>");
                    const_cast<core::EventMessage&>(event_message).canceled = true;
                    return;
                }
                if (world == "exit") {
                    utils::PacketUtils::send_chat_message(player_, "`4You cannot warp to the exit world.");
                    const_cast<core::EventMessage&>(event_message).canceled = true;
                    return;
                }
                if (world.size() > 23) {
                    utils::PacketUtils::send_chat_message(player_, "`4World name too long, try again.");
                    const_cast<core::EventMessage&>(event_message).canceled = true;
                    return;
                }

                spdlog::info("[server] warp command detected from client, world='{}'", world);

                // Quit to exit first
                packet::message::Log quit_msg{};
                quit_msg.msg = "action|quit_to_exit";
                ByteStream<std::uint16_t> bs_quit;
                quit_msg.write(bs_quit);
                to_player->send_packet(bs_quit.get_data(), 0);

                std::this_thread::sleep_for(std::chrono::milliseconds(300));

                // Send join_request
                packet::message::Log join_msg{};
                join_msg.msg = fmt::format("action|join_request\nname|{}\ninvitedWorld|0", world);
                ByteStream<std::uint16_t> bs_join;
                join_msg.write(bs_join);
                bool join_ok = to_player->send_packet(bs_join.get_data(), 0);
                spdlog::info("[server] join_request send result: {}", join_ok);

                utils::PacketUtils::send_chat_message(player_, fmt::format("Warping to {}...", world));

                const_cast<core::EventMessage&>(event_message).canceled = true;
                return;
            }
        }

        // Forward original bytes to upstream if not canceled
        if (!event_message.canceled) {
            std::ignore = to_player->send_packet(byte_stream.get_data(), 0);
        }

        if (message.find("action|quit") != std::string::npos &&
            message.find("action|quit_to_exit") == std::string::npos) {
            player_->disconnect();
        }
    }
    else if (type == packet::NET_MESSAGE_GAME_PACKET) {
        packet::GameUpdatePacket game_update_packet{};
        byte_stream.read(game_update_packet);

        std::vector<std::byte> ext_data{};
        if (game_update_packet.data_size > 0) {
            byte_stream.read_vector(ext_data, game_update_packet.data_size);
        }

        const core::EventPacket event_packet{ *player_, *to_player, game_update_packet, ext_data };
        event_packet.from = core::EventFrom::FromClient;
        core_->get_event_dispatcher().dispatch(event_packet);

        if (core_->get_config().get<bool>("log.printGameUpdatePacket")) {
            spdlog::info(
                "Incoming GameUpdatePacket {} ({}) from client: {:p}\n",
                magic_enum::enum_name(game_update_packet.type),
                magic_enum::enum_integer(game_update_packet.type),
                spdlog::to_hex(byte_stream.get_data())
            );
        }

        if (!event_packet.canceled) {
            // Forward original combined bytes (header + ext) to upstream
            std::ignore = to_player->send_packet(byte_stream.get_data(), 0);
        }

        if (game_update_packet.type == packet::PACKET_DISCONNECT) {
            // Because Growtopia's client is force recreate the ENetHost when the client is
            // disconnected, we need to disconnect the client immediately.
            player_->disconnect_now();
            on_disconnect(peer);
        }
    }
    else {
        spdlog::warn(
            "Got an unknown packet type coming in from the address {}:{}:",
            network::format_ip_address(peer->address.host),
            peer->address.port
        );
        spdlog::warn("\t{} ({})", magic_enum::enum_name(type), magic_enum::enum_integer(type));
        std::ignore = to_player->send_packet(byte_stream.get_data(), 0);
    }
}

void Server::on_disconnect(ENetPeer* peer)
{
    spdlog::info(
        "The server just lost a connection from the address {}:{}!",
        network::format_ip_address(peer->address.host),
        peer->address.port
    );

    if (!player_) {
        return;
    }

    const core::EventDisconnection event_disconnection{ *player_ };
    event_disconnection.from = core::EventFrom::FromClient;
    core_->get_event_dispatcher().dispatch(event_disconnection);

    delete player_;
    player_ = nullptr;

    const player::Player* to_player{ core_->get_client()->get_player() };
    if (!to_player) {
        return;
    }

    enet_host_flush(host_); // Flush all outgoing packets before disconnecting
    to_player->disconnect_now();
    core_->get_client()->on_disconnect(to_player->get_peer());
}

} // namespace server
