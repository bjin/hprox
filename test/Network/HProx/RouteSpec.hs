-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

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

    it "finds the first matching route after current route sorting" $ do
      let catchAll = ReverseRoute Nothing "/api/" "catch-all:80"
          shorterHost = ReverseRoute (Just "example.com") "/" "shorter-host:80"
          longerHost = ReverseRoute (Just "example.com") "/api/" "longer-host:80"
      findMatchingRoute [catchAll, shorterHost, longerHost] (Just "example.com:8080") "/api/users"
        `shouldBe` Just longerHost

    it "uses hostless routes for any request host when no host-specific route matches" $ do
      let catchAll = ReverseRoute Nothing "/api/" "catch-all:80"
          hostRoute = ReverseRoute (Just "example.com") "/api/" "host:80"
      findMatchingRoute [catchAll, hostRoute] (Just "other.example") "/api/users"
        `shouldBe` Just catchAll

    it "does not match host-specific routes without a request host" $ do
      let route = ReverseRoute (Just "example.com") "/api/" "host:80"
      findMatchingRoute [route] Nothing "/api/users" `shouldBe` Nothing

    it "rewrites raw paths by dropping the configured prefix but preserving one slash" $ do
      let route = ReverseRoute Nothing "/api/" "backend:80"
          rewrite = rewriteReverseProxyRequest route [] "/api/users"
      rewriteRawPath rewrite `shouldBe` "/users"

    it "applies the current drop-based raw-path rewrite even if the route prefix is not present" $ do
      let route = ReverseRoute Nothing "/api/" "backend:80"
          rewrite = rewriteReverseProxyRequest route [] "/other"
      rewriteRawPath rewrite `shouldBe` "er"

    it "selects secure upstream behavior only for port 443" $ do
      let secure = rewriteReverseProxyRequest (ReverseRoute Nothing "/" "secure.example:443") [] "/"
          defaultPort = rewriteReverseProxyRequest (ReverseRoute Nothing "/" "plain.example") [] "/"
      rewriteUpstream secure `shouldBe` "secure.example"
      rewritePort secure `shouldBe` 443
      rewriteSecure secure `shouldBe` True
      rewriteUpstream defaultPort `shouldBe` "plain.example"
      rewritePort defaultPort `shouldBe` 80
      rewriteSecure defaultPort `shouldBe` False

    it "strips current proxy, forwarded, CDN, X-Real-IP, and X-Scheme headers" $ do
      let route = ReverseRoute Nothing "/" "backend:80"
          headers =
            [ ("Proxy-Connection", "keep-alive")
            , ("X-Forwarded-For", "127.0.0.1")
            , ("cf-ray", "ray")
            , ("cdn-loop", "loop")
            , ("X-Real-IP", "127.0.0.1")
            , ("X-Scheme", "https")
            , ("Authorization", "keep")
            ]
          rewrite = rewriteReverseProxyRequest route headers "/"
      rewriteHeaders rewrite `shouldBe` [("Host", "backend"), ("Authorization", "keep")]

    it "rewrites the request Host to the upstream host" $ do
      let route = ReverseRoute Nothing "/" "backend.example:8080"
          rewrite = rewriteReverseProxyRequest route [("Host", "original.example")] "/"
      rewriteRequestHost rewrite `shouldBe` Just "backend.example"
      rewriteHeaders rewrite `shouldBe` [("Host", "backend.example")]
