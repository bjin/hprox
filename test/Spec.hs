-- SPDX-License-Identifier: Apache-2.0

module Main
  ( main
  ) where

import Network.HProx.AuthSpec       qualified as AuthSpec
import Network.HProx.ConfigSpec     qualified as ConfigSpec
import Network.HProx.DoHSpec        qualified as DoHSpec
import Network.HProx.HeadersSpec    qualified as HeadersSpec
import Network.HProx.MiddlewareSpec qualified as MiddlewareSpec
import Network.HProx.ProxySpec      qualified as ProxySpec
import Network.HProx.PureSpec       qualified as PureSpec
import Network.HProx.RouteSpec      qualified as RouteSpec
import Network.HProx.RuntimeSpec    qualified as RuntimeSpec
import Network.HProx.TLSSpec        qualified as TLSSpec
import Test.Hspec


main :: IO ()
main = hspec $ do
  describe "hprox test suite" $
    it "runs" $
      True `shouldBe` True
  AuthSpec.spec
  ConfigSpec.spec
  DoHSpec.spec
  PureSpec.spec
  HeadersSpec.spec
  MiddlewareSpec.spec
  RouteSpec.spec
  ProxySpec.spec
  TLSSpec.spec
  RuntimeSpec.spec
