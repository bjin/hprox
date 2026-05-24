-- SPDX-License-Identifier: Apache-2.0

module Network.HProx.NaiveSpec
  ( spec
  ) where

import Data.ByteString   qualified as BS
import Data.Conduit
import Data.Conduit.List qualified as CL
import Network.Wai

import Network.HProx.Naive

import Test.Hspec

spec :: Spec
spec = do
  describe "parseRequestForPadding" $ do
    it "selects the first supported padding type from the request header" $ do
      parseRequestForPadding defaultRequest
        { requestHeaders = [("Padding-Type-Request", "unknown,1,0")]
        }
        `shouldBe` Just Variant1

    it "falls back to the legacy Padding header" $ do
      parseRequestForPadding defaultRequest
        { requestHeaders = [("Padding", "opaque")]
        }
        `shouldBe` Just Variant1

    it "rejects requests without supported padding headers" $
      parseRequestForPadding defaultRequest
        { requestHeaders = [("Padding-Type-Request", "unknown")]
        }
        `shouldBe` Nothing

  describe "padding conduits" $ do
    it "round-trips NoPadding without changing chunks" $ do
      chunks <- runConduit $ CL.sourceList ["hello", "world"] .| addPaddingConduit NoPadding .| removePaddingConduit NoPadding .| CL.consume
      chunks `shouldBe` ["hello", "world"]

    it "round-trips Variant1 payloads without depending on random padding bytes" $ do
      chunks <- runConduit $ CL.sourceList [BS.replicate 512 65] .| addPaddingConduit Variant1 .| removePaddingConduit Variant1 .| CL.consume
      BS.concat chunks `shouldBe` BS.replicate 512 65
