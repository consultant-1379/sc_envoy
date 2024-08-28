
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <cstdint>
#include <iostream>
#include <vector>
#include "benchmark/benchmark.h"
#include "include/nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace EricProxy {

static uint32_t fastMod(const uint32_t& input, const uint32_t& ceil) {

    return (input >= ceil ? input % ceil : input);
}

static uint32_t regularMod(const uint32_t& input, const uint32_t& ceil){

    return (input % ceil);

}

static void Mod_FastMod(benchmark::State& state){
    std::vector<uint32_t> dividend = {32,47,89,12,34,99,173,97};
    std::vector<uint32_t> divisor = {11,6,84,108,45,234,89,193,21};
    for(auto _ : state) {
    for(const auto& entry: divisor)
        {
            for(const auto& div: dividend){
                const auto& res = fastMod(div, entry);
                EXPECT_TRUE(res < 200);
            } 
        }
    }

}

BENCHMARK(Mod_FastMod);

static void Mod_RegularMod(benchmark::State& state){
    std::vector<uint32_t> dividend = {32,47,89,12,34,99,173,97};
    std::vector<uint32_t> divisor = {11,6,84,108,45,234,89,193,21};
    for(auto _ : state){
        for(const auto& entry: divisor)
        {
            for(const auto& div: dividend){
                const auto& res = regularMod(div, entry);
                EXPECT_TRUE(res < 200);
            } 
        }
    }


}

BENCHMARK(Mod_RegularMod);

} // namespace EricProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy