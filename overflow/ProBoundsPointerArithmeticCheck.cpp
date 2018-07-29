//===--- ProBoundsPointerArithmeticCheck.cpp - clang-tidy------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "ProBoundsPointerArithmeticCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace cppcoreguidelines {

void ProBoundsPointerArithmeticCheck::registerMatchers(MatchFinder *Finder) {
  if (!getLangOpts().CPlusPlus)
    return;

  // Flag all operators +, -, +=, -=, ++, -- that result in a pointerpointerType()
  Finder->addMatcher(
      binaryOperator(
          anyOf(hasOperatorName("+"), hasOperatorName("-"), hasOperatorName("*"),
                hasOperatorName("+="), hasOperatorName("-=")),
          //hasType(pointerType()),
          hasType(isUnsignedInteger()),
          unless(hasLHS(ignoringImpCasts(declRefExpr(to(isImplicit()))))))
          .bind("expr"),
      this);

}

void ProBoundsPointerArithmeticCheck::check(
    const MatchFinder::MatchResult &Result) {
  const auto *MatchedExpr = Result.Nodes.getNodeAs<Expr>("expr");

  diag(MatchedExpr->getExprLoc(), " potential overflow! ");
}

} // namespace cppcoreguidelines
} // namespace tidy
} // namespace clang
