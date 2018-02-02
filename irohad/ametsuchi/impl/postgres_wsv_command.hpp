/**
 * Copyright Soramitsu Co., Ltd. 2017 All Rights Reserved.
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

#ifndef IROHA_POSTGRES_WSV_COMMAND_HPP
#define IROHA_POSTGRES_WSV_COMMAND_HPP

#include "ametsuchi/wsv_command.hpp"
#include "postgres_wsv_common.hpp"

namespace iroha {
  namespace ametsuchi {
    class PostgresWsvCommand : public WsvCommand {
     public:
      explicit PostgresWsvCommand(pqxx::nontransaction &transaction);
      WsvCommandResult insertRole(
          const std::string &role_name) override;

      WsvCommandResult insertAccountRole(
          const std::string &account_id,
          const std::string &role_name) override;
      WsvCommandResult deleteAccountRole(
          const std::string &account_id,
          const std::string &role_name) override;

      WsvCommandResult insertRolePermissions(
          const std::string &role_id,
          const std::set<std::string> &permissions) override;

      WsvCommandResult insertAccount(
          const model::Account &account) override;
      WsvCommandResult updateAccount(
          const model::Account &account) override;
      WsvCommandResult setAccountKV(const std::string &account_id,
                                    const std::string &creator_account_id,
                                    const std::string &key,
                                    const std::string &val) override;
      WsvCommandResult insertAsset(const model::Asset &asset) override;
      WsvCommandResult upsertAccountAsset(
          const model::AccountAsset &asset) override;
      WsvCommandResult insertSignatory(
          const pubkey_t &signatory) override;
      WsvCommandResult insertAccountSignatory(
          const std::string &account_id,
          const pubkey_t &signatory) override;
      WsvCommandResult deleteAccountSignatory(
          const std::string &account_id,
          const pubkey_t &signatory) override;
      WsvCommandResult deleteSignatory(
          const pubkey_t &signatory) override;
      WsvCommandResult insertPeer(const model::Peer &peer) override;
      WsvCommandResult deletePeer(const model::Peer &peer) override;
      WsvCommandResult insertDomain(
          const model::Domain &domain) override;
      WsvCommandResult insertAccountGrantablePermission(
          const std::string &permittee_account_id,
          const std::string &account_id,
          const std::string &permission_id) override;

      WsvCommandResult deleteAccountGrantablePermission(
          const std::string &permittee_account_id,
          const std::string &account_id,
          const std::string &permission_id) override;

     private:
      const size_t default_tx_counter = 0;

      pqxx::nontransaction &transaction_;
      logger::Logger log_;

      using ExecuteType = decltype(makeExecuteResult(transaction_, log_));
      ExecuteType execute_;

      // TODO: refactor to return Result when it is introduced IR-744
      WsvCommandResult makeCommandResult(
          expected::Result<pqxx::result, std::string> result,
          const std::string &error_message) const noexcept ;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_WSV_COMMAND_HPP
