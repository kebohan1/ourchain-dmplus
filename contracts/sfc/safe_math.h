#include <assert>

uint64_t safeAdd(uint64_t x, uint64_t y) {
    uint64_t z = x + y;
    assert((z >= x) && (z >= y));
    return z;
}

uint64_t safeSubtract(uint64_t x, uint64_t y) {
    assert(x >= y);
    uint64_t z = x - y;
    return z;
}

uint64_t safeMult(uint64_t x, uint64_t y) {
    uint64_t z = x * y;
    assert((x == 0) || (z/x == y));
    return z;
}

uint64_t min(uint64_t a, uint64_t b) {
    if (a < b) {
        return a;
    } else {
        return b;
    }
}

uint64_t max(uint64_t a, uint64_t b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}