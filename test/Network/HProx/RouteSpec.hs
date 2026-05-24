-- SPDX-License-Identifier: Apache-2.0

module Network.HProx.RouteSpec
  ( spec
  ) where

import Network.HProx.Route

import Test.Hspec

spec :: Spec
spec =
  describe "ReverseRoute" $ do
    it "converts from the public Config reverse-route tuple shape" $
      fromReverseRouteTuple (Just "example.com", "/api/", "backend:80")
        `shouldBe` ReverseRoute
          { routeHost = Just "example.com"
          , routePrefix = "/api/"
          , routeUpstream = "backend:80"
          }

    it "sorts domain-specific routes before catch-all routes and longer prefixes first" $ do
      let catchAllLong = ReverseRoute Nothing "/longer/" "catch-long:80"
          catchAllShort = ReverseRoute Nothing "/" "catch-short:80"
          hostShort = ReverseRoute (Just "example.com") "/" "host-short:80"
          hostLong = ReverseRoute (Just "example.com") "/api/" "host-long:80"
      sortReverseRoutes [catchAllShort, hostShort, catchAllLong, hostLong]
        `shouldBe` [hostLong, hostShort, catchAllLong, catchAllShort]

    it "matches hostless routes against any request host" $ do
      let route = ReverseRoute Nothing "/" "backend:80"
      hostMatches route Nothing `shouldBe` True
      hostMatches route (Just "example.com") `shouldBe` True

    it "matches host-specific routes only against the same host" $ do
      let route = ReverseRoute (Just "example.com") "/" "backend:80"
      hostMatches route Nothing `shouldBe` False
      hostMatches route (Just "example.com") `shouldBe` True
      hostMatches route (Just "other.example") `shouldBe` False

    it "matches prefixes using the current raw ByteString prefix policy" $ do
      let route = ReverseRoute Nothing "/api" "backend:80"
      prefixMatches route "/api" `shouldBe` True
      prefixMatches route "/api/v1" `shouldBe` True
      prefixMatches route "/other" `shouldBe` False
