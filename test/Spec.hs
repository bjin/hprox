-- SPDX-License-Identifier: Apache-2.0

module Main
  ( main
  ) where

import Network.HProx.PureSpec qualified as PureSpec
import Test.Hspec


main :: IO ()
main = hspec $ do
  describe "hprox test suite" $
    it "runs" $
      True `shouldBe` True
  PureSpec.spec
