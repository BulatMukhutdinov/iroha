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

#include <boost/format.hpp>
#include "cryptography/crypto_provider/crypto_verifier.hpp"

using shared_model::detail::PolymorphicWrapper;
using shared_model::interface::Block;
using shared_model::interface::types::SignatureType;
using shared_model::crypto::CryptoVerifier;

namespace shared_model {
  namespace validation {

    static const auto kSignature = "signature";
    static const auto kTxsNumber = "txsNumber";

    Answer BlockValidator::validate(PolymorphicWrapper<Block> block) const {
      Answer answer;

      validate_signatures(answer, *block.get());
      validate_txsNumber(answer, block->txsNumber());

      return answer;
    }

    void BlockValidator::validate_signatures(Answer &answer,
                                             const Block &block) const {
      if(block.signatures().empty()){
        answer.addReason(kSignature, {"unsigned block"});
        return;
      }

      for (const auto &sig : block.signatures()) {
        bool is_valid = CryptoVerifier<>::verify(
            sig->signedData(), block.payload(), sig->publicKey());

        if (not is_valid) {
          std::string reason =
              "signature of " + sig->publicKey().hex() + " is invalid";
          answer.addReason(kSignature, {reason});
        }
      }
    }

    void BlockValidator::validate_txsNumber(
        Answer &answer, const Block::TransactionsNumberType &txsNumber) const {
      if (txsNumber == 0) {
        answer.addReason(kTxsNumber,
                         {"number of transactions in block can not be 0"});
      }
    }
  }
}
