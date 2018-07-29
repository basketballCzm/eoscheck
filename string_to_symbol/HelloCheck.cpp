//===--- HelloCheck.cpp - clang-tidy---------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "HelloCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Lex/Lexer.h"

using namespace clang::ast_matchers;


namespace clang {
namespace tidy {
namespace readability {

void HelloCheck::registerMatchers(MatchFinder *Finder) {
	if(!getLangOpts().CPlusPlus){
		return;
	}
	// FIXME: Add matchers.
	Finder->addMatcher(callExpr(callee(functionDecl(hasAnyName("string_to_symbol")))).bind("function"),this);
}

void HelloCheck::check(const MatchFinder::MatchResult &Result) {
// FIXME: Add callback implementation.
  const auto *MatchedDecl = Result.Nodes.getNodeAs<CallExpr>("x");
  if (MatchedDecl)
  	diag(MatchedDecl->getLocStart(), "Make sure the token name size is checked before calling the string_to_symbol function")
      << FixItHint::CreateInsertion(MatchedDecl->getLocStart(), "eosio_assert(symbolname.size() <= 255)");
}

} // namespace readability
} // namespace tidy
} // namespace clang
