/**
 * Copyright Soramitsu Co., Ltd. 2018 All Rights Reserved.
 * http://soramitsu.co.jp
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "validators/block_validator.hpp"
#include <gtest/gtest.h>
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "validators/answer.hpp"

using namespace shared_model;
using namespace shared_model::detail;
using wBlock = shared_model::detail::PolymorphicWrapper<interface::Block>;
using shared_model::validation::BlockValidator;

// static wBlock TestWrappedBlockBuilder() {
//  std::string hash = "hash?";
//  auto b = TestBlockBuilder().createdTime(1).height(1).txNumber(3).build();
//
//  return makePolymorphic<Block>(std::move(b));
//}

class BlockValidatorFixture : public BlockValidator, public ::testing::Test {
 public:
};

/**
 * @given a block without signatures
 * @when passed to block_validator
 * @then reason is "no signatures"
 */
TEST_F(BlockValidatorFixture, NoSignatures) {
  Answer answer;
  auto block = TestBlockBuilder().height(1).build();
  this->validate_signatures(answer, block);
  ASSERT_TRUE(answer.hasErrors());
}

/**
 * @given a block without signatures
 * @when passed to block_validator
 * @then reason is "no signatures"
 */
TEST_F(BlockValidatorFixture, OneSignature) {
  Answer answer;
  auto block = TestBlockBuilder().height(1).build();
  this->validate_signatures(answer, block);
  ASSERT_TRUE(answer.hasErrors());
}