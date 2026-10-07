#pragma once
#include "vtil/vtil"
#include "operative.hpp"

namespace vtil::flags {
    inline const register_desc CF = { register_physical | register_flags, 0, 1, 0 };
    inline const register_desc PF = { register_physical | register_flags, 0, 1, 2 };
    inline const register_desc AF = { register_physical | register_flags, 0, 1, 4 };
    inline const register_desc ZF = { register_physical | register_flags, 0, 1, 6 };
    inline const register_desc SF = { register_physical | register_flags, 0, 1, 7 };
    inline const register_desc IF = { register_physical | register_flags, 0, 1, 9 };
    inline const register_desc DF = { register_physical | register_flags, 0, 1, 10 };
    inline const register_desc OF = { register_physical | register_flags, 0, 1, 11 };

    static operative zero(const operative& value) {
        return value == 0;
    }

    static operative aux_carry(const operative& lhs, const operative& rhs, const operative& result) {
        return ((lhs ^ rhs ^ result) & 0x10) != 0;
    }

    static operative aux_carry(const operative& lhs, const operative& rhs, const operative& carry, const operative& result) {
        return ((lhs ^ rhs ^ carry ^ result) & 0x10) != 0;
    }

    static operative sign(const operative& value) {
        return (value < 0);
    }

    static operative parity(const operative& value) {
        return ((value & 0xFF).popcnt() & 1) == 0;
    }

    enum flag_operation : uint32_t {
        add, sub, mul, imul, div, idiv,
        band, bor, bxor, bshl, bshr
    };

    template <flag_operation op>
    struct overflow;

    template<>
    struct overflow<add> {
        static operative flag(const operative& lhs, const operative& rhs, const operative& result) {
            auto lhs_sign = sign(lhs);
            auto rhs_sign = sign(rhs);
            auto res_sign = sign(result);
            return (lhs_sign ^ res_sign) & (rhs_sign ^ res_sign);
        }
    };

    template<>
    struct overflow<sub> {
        static operative flag(const operative& lhs, const operative& rhs, const operative& result) {
            auto lhs_sign = sign(lhs);
            auto rhs_sign = sign(rhs);
            auto res_sign = sign(result);
            return (lhs_sign ^ rhs_sign) & (lhs_sign ^ res_sign);
        }
    };

    template<>
    struct overflow<band> {
        static operative flag(const operative&, const operative&, const operative&) { return { 0 }; }
    };

    template<>
    struct overflow<bor> {
        static operative flag(const operative&, const operative&, const operative&) { return { 0 }; }
    };

    template<>
    struct overflow<bxor> {
        static operative flag(const operative&, const operative&, const operative&) { return { 0 }; }
    };

    template <flag_operation Op>
    struct carry;

    template<>
    struct carry<add> {
        static operative flag(const operative& lhs, const operative& rhs, const operative& result) {
            return __ugreat(lhs, result);
        }
    };

    template<>
    struct carry<sub> {
        static operative flag(const operative& lhs, const operative& rhs, const operative& result) {
            return __ugreat(result, lhs);
        }
    };

    template<>
    struct carry<band> {
        static operative flag(const operative&, const operative&, const operative&) { return { 0 }; }
    };

    template<>
    struct carry<bor> {
        static operative flag(const operative&, const operative&, const operative&) { return { 0 }; }
    };

    template<>
    struct carry<bxor> {
        static operative flag(const operative&, const operative&, const operative&) { return { 0 }; }
    };
}

namespace vtil {
    template<flags::flag_operation op>
    void process_flags(vtil::basic_block* block, const operand& lhs,
                       const operand& rhs, const operand& result) {
        block
            ->mov(flags::OF, flags::overflow<op>::flag(lhs, rhs, result))
            ->mov(flags::CF, flags::carry<op>::flag(lhs, rhs, result))
            ->mov(flags::SF, flags::sign(result))
            ->mov(flags::ZF, flags::zero(result))
            ->mov(flags::AF, flags::aux_carry(lhs, rhs, result))
            ->mov(flags::PF, flags::parity(result));
    }
}
