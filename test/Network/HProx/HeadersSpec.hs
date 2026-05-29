-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.HeadersSpec
  ( spec
  ) where

import Network.HProx.Headers

import Test.Hspec

spec :: Spec
spec =
    describe "header policy helpers" $ do
        it "detects proxy, forwarded, and CDN header families" $ do
            isProxyHeader "Proxy-Connection" `shouldBe` True
            isForwardedHeader "X-Forwarded-For" `shouldBe` True
            isCDNHeader "cf-ray" `shouldBe` True
            isCDNHeader cdnLoopHeader `shouldBe` True

            isForwardedHeader "Forwarded" `shouldBe` True
            isForwardedHeader "forwarded-for" `shouldBe` False
        it "preserves the current strip-header policy" $ do
            map isProxyStripHeader ["Proxy-Connection", "X-Forwarded-Proto", "cf-ray", xRealIPHeader, xSchemeHeader]
                `shouldBe` replicate 5 True
            isProxyStripHeader "Authorization" `shouldBe` False
            isProxyStripHeader "Forwarded" `shouldBe` True
            isProxyStripHeader "X-Not-Forwarded" `shouldBe` False

        it "compares protocol header values case-insensitively" $ do
            headerValueEquals "https" "HTTPS" `shouldBe` True
            headerValueEquals "http" "HtTp" `shouldBe` True
            headerValueEquals "http" "https" `shouldBe` False
