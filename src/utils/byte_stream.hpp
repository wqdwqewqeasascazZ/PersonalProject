#pragma once
#include <vector>
#include <string>

template <typename LengthType = std::uint16_t>
class ByteStream {
public:
    ByteStream()
        : data_{ std::vector<std::byte>() }
        , read_offset_{ 0 }
    {

    }

    ByteStream(std::byte* data, const std::size_t length)
        : data_{ std::vector(data, data + length) }
        , read_offset_{ 0 }
    {

    }

    void write_data(const void* ptr, const std::size_t size)
    {
        const auto begin{ static_cast<const std::byte*>(ptr) };
        const std::byte* end{ begin + size };
        data_.insert(data_.end(), begin, end);
    }

    void write_vector(const std::vector<std::byte>& vec, const bool write_length_info = true)
    {
        if (write_length_info) {
            write(static_cast<LengthType>(vec.size()));
        }

        write_data(vec.data(), vec.size());
    }

    template <typename T>
    void write(const T& value)
    {
        write_data(&value, sizeof(T));
    }

    void write(const char* c_str, const bool write_length_info = true)
    {
        write(std::string{ c_str }, write_length_info);
    }

    void write(const std::string& str, const bool write_length_info = true)
    {
        if (write_length_info) {
            write(static_cast<LengthType>(str.size()));
        }

        write_data(str.c_str(), str.size());
    }

    template <typename T>
    ByteStream& operator<<(const T& value)
    {
        write(value);
        return *this;
    }

    bool read_data(void* ptr, const std::size_t size)
    {
        if (data_.size() - read_offset_ < size) {
            return false;
        }

        std::memcpy(ptr, data_.data() + read_offset_, size);
        read_offset_ += size;
        return true;
    }

    bool read_vector(std::vector<std::byte>& vec, LengthType length = 0)
    {
        if (length == 0) {
            if (!read<LengthType>(length)) {
                return false;
            }
        }

        if (data_.size() < static_cast<std::size_t>(length)) {
            return false;
        }

        vec.resize(length);
        read_data(&vec[0], length);
        return true;
    }

    template <typename T>
    bool read(T& value)
    {
        read_data(&value, sizeof(T));
        return true;
    }

    bool read(std::string& str, LengthType length = 0)
    {
        if (length == 0) {
            if (!read<LengthType>(length)) {
                return false;
            }
        }

        if (data_.size() < static_cast<std::size_t>(length)) {
            return false;
        }

        str.resize(static_cast<std::size_t>(length));
        read_data(&str[0], static_cast<std::size_t>(length));
        return true;
    }

    template <typename T>
    ByteStream& operator>>(T& value)
    {
        read(value);
        return *this;
    }

    void skip(const std::size_t size) { read_offset_ += size; }
    [[nodiscard]] std::size_t get_read_offset() const { return read_offset_; }
    [[nodiscard]] std::size_t get_size() const { return data_.size(); }
    [[nodiscard]] std::vector<std::byte> get_data() const { return data_; }

private:
    std::vector<std::byte> data_;
    std::size_t read_offset_;
};
