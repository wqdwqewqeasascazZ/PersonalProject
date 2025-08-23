#pragma once
#include "command_handler.hpp"
#include "../parser/parser.hpp"
#include "../../core/core.hpp"
#include "../../client/client.hpp"
#include "../../packet/game/core.hpp"
#include "../../utils/text_parse.hpp"
#include "../../core/logger.hpp"
#include "../../utils/packet_utils.hpp"
#include "../../server/server.hpp"
#include "../../player/player_compat.hpp"
#include "../../packet/packet_types.hpp"

#include <string>
#include <fmt/format.h>

namespace extension::command_handler {

class CommandHandlerExtension final : public ICommandHandlerExtension {
    core::Core* core_;
public:
    explicit CommandHandlerExtension(core::Core* core) : core_{ core } {}
    ~CommandHandlerExtension() override = default;

    void init() override {
        core_->get_event_dispatcher().prependListener(
            core::EventType::Message,
            [this](const core::EventMessage& event) {
                TextParse textParse(event.get_message().get_raw(), "|");
                std::string command = textParse.get("text");

                if (command == "/proxy") {
                    auto* server_player = core_->get_server() ? core_->get_server()->get_player() : nullptr;
                    if (!server_player) {
                        spdlog::error("No server player available to send /proxy input.");
                        event.canceled = true;
                        return;
                    }

                    const std::string payload = "action|input\ntext|Hi from /proxy";

                    int result = player::compat::send_packet(
                        server_player,
                        static_cast<std::uint32_t>(packet::NET_MESSAGE_GENERIC_TEXT),
                        payload,
                        /*channel=*/0
                    );

                    spdlog::info("Proxy -> sent input payload to server (result={})", result);

                    event.canceled = true;
                    return;
                }
            }
        );
    }

    void free() override { delete this; }
};

} // namespace extension::command_handler
