-- SPDX-License-Identifier: Apache-2.0

module Main
  ( main
  ) where

import Test.Hspec

main :: IO ()
main = hspec $
  describe "hprox test suite" $
    it "runs" $
      True `shouldBe` True
