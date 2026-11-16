// msgbuf.cpp
#include <cstring>
#include "msgbuf.h"

MsgBuf::MsgBuf(std::size_t n) : len_(n), data_(new char[n])
{
    std::memset(data_, 0, n);
}

MsgBuf::~MsgBuf()
{
    delete[] data_;
}
