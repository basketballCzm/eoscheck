#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>

//using namespace eosio;

class simpletoken : public eosio::contract {
   public:
      simpletoken( account_name self )
      :contract(self),_accounts( _self, _self){}
      using contract::contract;

      void transfer( account_name from, account_name to, uint64_t quantity ) {
         require_auth( from );

         const auto& fromacnt = _accounts.get( from );
         const auto& toacnt = _accounts.get( to );

         //eosio_assert( from1.balance >= quantity, "overdrawn balance" );

         eosio::print( "Before : ", eosio::name{from}, " : ", fromacnt.balance, " \t ", eosio::name{to}, " : ", toacnt.balance, "\n" );
         eosio::print( "Tranfer from ", eosio::name{from}, " to ", eosio::name{to}, " amount = ", quantity, "\n" );

         _accounts.modify( fromacnt, from, [&]( auto& a ){ a.balance -= quantity; } );
         add_balance( from, to, quantity );

         eosio::print( "Result : ", eosio::name{from}, " : ", fromacnt.balance, " \t ", eosio::name{to}, " : ", toacnt.balance );
      }

      void transfer2( account_name from, account_name to1, account_name to2, uint64_t balance) {
        //print("transfer");
        require_auth(from);
        const auto& fromacnt = _accounts.get( from );
        const auto& toacnt1 = _accounts.get( to1 );
        const auto& toacnt2 = _accounts.get( to2 );
        //account fromaccount;

        //require_recipient(from);
        //require_recipient(to.name0);
        //require_recipient(to.name1);
        //require_recipient(to.name2);
        //require_recipient(to.name3);

        //eosio_assert(is_balance_within_range(balance), "invalid balance");
        eosio_assert(balance > 0, "must transfer positive balance");        //unnecessary

        uint64_t amount = balance * 2;

        //int itr = db_find_i64(_self, symble, N(table), from);
        //eosio_assert(itr >= 0, "Sub--wrong name");
        //db_get_i64(itr, &fromaccount, sizeof(account));
        eosio_assert(fromacnt.balance >= amount, "overdrawn balance");      //vulnerability

        eosio::print( "Before account : ", eosio::name{from}, " \t ", eosio::name{to1}, " \t ", eosio::name{to2}, "\n" );
        eosio::print( "Before balance : ", fromacnt.balance, " \t ", toacnt1.balance, " \t ", toacnt2.balance, "\n" );

        //sub_balance(symble, from, amount);
        _accounts.modify( fromacnt, from, [&]( auto& a ){ a.balance -= amount; } );

        add_balance( from, to1, balance );
        add_balance( from, to2, balance );

        eosio::print( "Result account : ", eosio::name{from}, " \t ", eosio::name{to1}, " \t ", eosio::name{to2}, "\n" );
        eosio::print( "Result account : ", fromacnt.balance, " \t ", toacnt1.balance, " \t ", toacnt2.balance );
      }

      void issue( account_name to, uint64_t quantity ) {
         require_auth( _self );
         add_balance( _self, to, quantity );

         const auto& toacnt = _accounts.get( to );
         eosio::print( "Issue resoult : ", eosio::name{to}, " : ", toacnt.balance );
      }

   private:
      struct account {
         account_name owner;
         uint64_t     balance;

         uint64_t primary_key()const { return owner; }
      };

      eosio::multi_index<N(accounts), account> _accounts;

      void add_balance( account_name payer, account_name to, uint64_t q ) {
         auto toitr = _accounts.find( to );
         if( toitr == _accounts.end() ) {
           _accounts.emplace( payer, [&]( auto& a ) {
              a.owner = to;
              a.balance = q;
           });
         } else {
           _accounts.modify( toitr, 0, [&]( auto& a ) {
              a.balance += q;
              eosio_assert( a.balance >= q, "overflow detected" );
           });
         }
      }
};

EOSIO_ABI( simpletoken, (transfer2)(transfer)(issue) )
