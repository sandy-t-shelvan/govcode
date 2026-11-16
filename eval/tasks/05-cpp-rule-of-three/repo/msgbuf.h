#ifndef MSGBUF_H
#define MSGBUF_H
#include <cstddef>

// Fixed-size message buffer. Copies must be independent (deep copy).
class MsgBuf {
public:
    explicit MsgBuf(std::size_t n);
    ~MsgBuf();
    char& operator[](std::size_t i) { return data_[i]; }
    char operator[](std::size_t i) const { return data_[i]; }
    std::size_t size() const { return len_; }
private:
    std::size_t len_;
    char* data_;
};
#endif
