#pragma once
#include "vtil/vtil"

namespace vtil {
    struct operative : math::operable<operative> {
        operand op;
        inline static thread_local batch_translator* translator = nullptr;

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        operative(T value)
            : op(value, sizeof(T) * 8) {}

        operative(operand op)
            : op(std::move(op)) {}

        operative(const operative& lhs, math::operator_id opr, const operative& rhs) {
            auto elhs = lhs.op.is_register()
                ? symbolic::CTX[lhs.op.reg()]
                : symbolic::expression{ lhs.op.imm().uval, lhs.op.bit_count() };
            auto erhs = rhs.op.is_register()
                ? symbolic::CTX[rhs.op.reg()]
                : symbolic::expression{ rhs.op.imm().uval, rhs.op.bit_count() };

            op = *translator << symbolic::variable::pack_all(symbolic::expression{ elhs, opr, erhs });
        }

        operative(math::operator_id opr, const operative& rhs) {
            auto erhs = rhs.op.is_register()
                ? symbolic::CTX[rhs.op.reg()]
                : symbolic::expression{ rhs.op.imm().uval, rhs.op.bit_count() };

            op = *translator << symbolic::variable::pack_all(symbolic::expression{ opr, erhs });
        }

        bitcnt_t bit_count() { return op.bit_count(); }

        operative& operator=(const operative& o) {
            translator->block->push_back({ &ins::mov, { op, o.op } });
            return *this;
        }

        operative operator!=(const operative& o) { return (*this == o) == 0; }
        operative operator&&(const operative& o) { return (*this != 0) & (o != 0); }
        operative operator||(const operative& o) { return (*this != 0) | (o != 0); }

        operative popcnt() const {
            auto tmp = translator->block->tmp(32);
            translator->block->mov(tmp, op)->popcnt(tmp);
            return operand{ tmp };
        }

        operative zext(bitcnt_t bit_size) const {
            auto tmp = translator->block->tmp(bit_size);
            translator->block->mov(tmp, op);
            return { operand{ tmp } };
        }

        operative sext(bitcnt_t bit_size) const {
            auto tmp = translator->block->tmp(bit_size);
            translator->block->movsx(tmp, op);
            return { operand{ tmp } };
        }
    };

    template<>
    struct register_cast<operative> {
        auto& operator()(const operative& opr) { return opr.op.descriptor; }
        auto&& operator()(operative&& opr) { return std::move(opr.op.descriptor); }
    };
}
