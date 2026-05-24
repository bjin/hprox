-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.MiddlewareSpec
  ( spec
  ) where

import Data.ByteString.Char8      qualified as BS8
import Data.ByteString.Lazy.Char8 qualified as LBS8
import Network.HTTP.Types         qualified as HT
import Network.Wai
import Network.Wai.Test

import Network.HProx.Impl

import Test.Hspec

spec :: Spec
spec = do
  describe "healthCheckProvider" $ do
    it "returns 200 okay for the health endpoint" $ do
      response <- runApp healthCheckProvider (requestPath "/.hprox/health")
      simpleStatus response `shouldBe` HT.status200
      simpleBody response `shouldBe` "okay"

    it "falls through outside the health endpoint" $ do
      response <- runApp healthCheckProvider (requestPath "/not-health")
      simpleStatus response `shouldBe` fallbackStatus
      simpleBody response `shouldBe` fallbackBody

  describe "acmeProvider" $ do
    it "serves an insecure challenge when a thumbprint is configured" $ do
      response <- runApp (acmeProvider testSettings) (requestPath "/.well-known/acme-challenge/token")
      simpleStatus response `shouldBe` HT.status200
      simpleBody response `shouldBe` "token.thumbprint"
      lookup "Content-Type" (simpleHeaders response) `shouldBe` Just "text/plain"

    it "falls through for secure ACME requests" $ do
      response <- runApp (acmeProvider testSettings) $ (requestPath "/.well-known/acme-challenge/token")
        { isSecure = True
        }
      simpleStatus response `shouldBe` fallbackStatus

    it "falls through without a configured thumbprint" $ do
      response <- runApp (acmeProvider testSettings { acmeThumbprint = Nothing }) (requestPath "/.well-known/acme-challenge/token")
      simpleStatus response `shouldBe` fallbackStatus

  describe "pacProvider" $ do
    it "uses forwarded host and lowercase https proto for the PAC response" $ do
      response <- runApp pacProvider $ (requestPath "/.hprox/config.pac")
        { requestHeaders = [("x-forwarded-host", "proxy.example"), ("x-forwarded-proto", "https")]
        }
      simpleStatus response `shouldBe` HT.status200
      simpleBody response `shouldBe` LBS8.unlines
        [ "function FindProxyForURL(url, host) {"
        , "  return \"HTTPS proxy.example:443\";"
        , "}"
        ]
      lookup "Content-Type" (simpleHeaders response) `shouldBe` Just "application/x-ns-proxy-autoconfig"

    it "uses Host and preserves an explicit host port for insecure PAC responses" $ do
      response <- runApp pacProvider $ (requestPath "/.hprox/config.pac")
        { requestHeaderHost = Just "proxy.example:8080"
        }
      simpleStatus response `shouldBe` HT.status200
      simpleBody response `shouldBe` LBS8.unlines
        [ "function FindProxyForURL(url, host) {"
        , "  return \"PROXY proxy.example:8080\";"
        , "}"
        ]

    it "treats forwarded proto values case-insensitively" $ do
      response <- runApp pacProvider $ (requestPath "/.hprox/config.pac")
        { requestHeaders = [("x-forwarded-host", "proxy.example"), ("x-forwarded-proto", "HTTPS")]
        }
      simpleStatus response `shouldBe` HT.status200
      simpleBody response `shouldBe` LBS8.unlines
        [ "function FindProxyForURL(url, host) {"
        , "  return \"HTTPS proxy.example:443\";"
        , "}"
        ]

    it "falls through without a host" $ do
      response <- runApp pacProvider (requestPath "/.hprox/config.pac")
      simpleStatus response `shouldBe` fallbackStatus

  describe "forceSSL" $ do
    it "redirects insecure origin-form requests with path and query to HTTPS" $ do
      response <- runApp (forceSSL testSettings) $ (requestPath "/docs")
        { requestHeaderHost = Just "example.com"
        , rawQueryString = "?q=1"
        }
      simpleStatus response `shouldBe` HT.status301
      lookup "Location" (simpleHeaders response) `shouldBe` Just "https://example.com/docs?q=1"

    it "redirects root origin-form requests to the HTTPS root" $ do
      response <- runApp (forceSSL testSettings) $ defaultRequest
        { requestHeaderHost = Just "example.com"
        , rawPathInfo = "/"
        }
      simpleStatus response `shouldBe` HT.status301
      lookup "Location" (simpleHeaders response) `shouldBe` Just "https://example.com/"

    it "redirects insecure absolute-form proxy requests to the parsed HTTPS target" $ do
      response <- runApp (forceSSL testSettings) $ defaultRequest
        { requestHeaderHost = Just "proxy.local"
        , rawPathInfo = "http://target.example:8080/docs"
        , rawQueryString = "?q=1"
        }
      simpleStatus response `shouldBe` HT.status301
      lookup "Location" (simpleHeaders response) `shouldBe` Just "https://target.example:8080/docs?q=1"

    it "omits default ports from absolute-form HTTPS redirect authorities" $ do
      response <- runApp (forceSSL testSettings) $ defaultRequest
        { requestHeaderHost = Just "proxy.local"
        , rawPathInfo = "http://target.example/docs"
        }
      simpleStatus response `shouldBe` HT.status301
      lookup "Location" (simpleHeaders response) `shouldBe` Just "https://target.example/docs"

    it "returns upgrade-required for insecure requests without Host" $ do
      response <- runApp (forceSSL testSettings) defaultRequest
      simpleStatus response `shouldBe` HT.mkStatus 426 "Upgrade Required"
      lookup "Upgrade" (simpleHeaders response) `shouldBe` Just "TLS/1.0, HTTP/1.1"

    it "falls through for secure requests" $ do
      response <- runApp (forceSSL testSettings) defaultRequest { isSecure = True }
      simpleStatus response `shouldBe` fallbackStatus

runApp :: Middleware -> Request -> IO SResponse
runApp middleware req = runSession (srequest $ SRequest req "") (middleware fallback)

requestPath :: String -> Request
requestPath path = setPath defaultRequest (BS8.pack path)

fallback :: Application
fallback _req respond = respond $ responseLBS fallbackStatus [("Content-Type", "text/plain")] fallbackBody

fallbackStatus :: HT.Status
fallbackStatus = HT.mkStatus 418 "fallback"

fallbackBody :: LBS8.ByteString
fallbackBody = "fallback"

testSettings :: ProxySettings
testSettings = ProxySettings
  { proxyAuth      = Nothing
  , passPrompt     = Just "hprox"
  , wsRemote       = Nothing
  , revRemoteMap   = []
  , hideProxyAuth  = False
  , naivePadding   = False
  , acmeThumbprint = Just "thumbprint"
  , logger         = \_ _ -> return ()
  }
