-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.ProxySpec
  ( spec
  ) where

import Data.ByteString.Lazy qualified as LBS
import Network.HTTP.Client  qualified as HC
import Network.HTTP.Types   qualified as HT
import Network.Wai
import Network.Wai.Test

import Network.HProx.Impl

import Test.Hspec

spec :: Spec
spec = do
  describe "HTTP proxy auth decisions" $ do
    it "challenges unauthorized HTTP proxy requests" $ do
      response <- runProxyApp (httpProxy authRequiredSettings) rawProxyRequest
      simpleStatus response `shouldBe` HT.status407
      lookup "Proxy-Authenticate" (simpleHeaders response) `shouldBe` Just "Basic realm=\"hprox\""

    it "falls back instead of challenging when hidden auth is enabled" $ do
      response <- runProxyApp (httpProxy hiddenAuthSettings) rawProxyRequest
      simpleStatus response `shouldBe` fallbackStatus
      simpleBody response `shouldBe` fallbackBody

  describe "CONNECT proxy auth decisions" $ do
    it "challenges unauthorized CONNECT requests" $ do
      response <- runConnectApp authRequiredSettings connectRequest
      simpleStatus response `shouldBe` HT.status407
      lookup "Proxy-Authenticate" (simpleHeaders response) `shouldBe` Just "Basic realm=\"hprox\""

    it "falls back instead of challenging CONNECT requests when hidden auth is enabled" $ do
      response <- runConnectApp hiddenAuthSettings connectRequest
      simpleStatus response `shouldBe` fallbackStatus
      simpleBody response `shouldBe` fallbackBody

  describe "HTTP proxy fallback decisions" $
    it "falls through for non-proxy GET requests" $ do
      response <- runProxyApp (httpProxy authRequiredSettings) defaultRequest
      simpleStatus response `shouldBe` fallbackStatus
      simpleBody response `shouldBe` fallbackBody


  describe "HTTP proxy target parsing" $ do
    it "selects raw absolute-URI proxy targets with default ports" $
      selectHttpProxyTarget rawProxyRequest
        `shouldBe` Just HttpProxyTarget
          { httpProxyTargetHost = "example.com"
          , httpProxyTargetPort = 80
          , httpProxyTargetRawPath = "/resource"
          }

    it "preserves bracketed IPv6 proxy targets without explicit ports" $
      selectHttpProxyTarget rawProxyRequest { rawPathInfo = "http://[::1]/resource" }
        `shouldBe` Just HttpProxyTarget
          { httpProxyTargetHost = "[::1]"
          , httpProxyTargetPort = 80
          , httpProxyTargetRawPath = "/resource"
          }

    it "treats HTTP/2 proxy scheme values case-insensitively" $
      selectHttpProxyTarget http2ProxyRequest { requestHeaders = [("X-Scheme", "HTTP")] }
        `shouldBe` Just HttpProxyTarget
          { httpProxyTargetHost = "example.com"
          , httpProxyTargetPort = 80
          , httpProxyTargetRawPath = "/resource"
          }

    it "rejects malformed explicit ports in raw absolute-URI requests" $
      selectHttpProxyTarget rawProxyRequest { rawPathInfo = "http://example.com:not-a-port/resource" }
        `shouldBe` Nothing

    it "rejects malformed explicit ports in Host-header proxy requests" $
      selectHttpProxyTarget hostHeaderProxyRequest { requestHeaderHost = Just "example.com:not-a-port" }
        `shouldBe` Nothing

    it "rejects HTTP/2 proxy requests without a Host header" $
      selectHttpProxyTarget http2ProxyRequest { requestHeaderHost = Nothing }
        `shouldBe` Nothing
runProxyApp :: (HC.Manager -> Middleware) -> Request -> IO SResponse

runProxyApp middleware req = do
  manager <- HC.newManager HC.defaultManagerSettings
  runSession (srequest $ SRequest req "") (middleware manager fallback)

runConnectApp :: ProxySettings -> Request -> IO SResponse
runConnectApp pset req = runSession (srequest $ SRequest req "") (httpConnectProxy pset fallback)

rawProxyRequest :: Request
rawProxyRequest = defaultRequest
  { requestMethod = "GET"
  , rawPathInfo = "http://example.com/resource"
  , requestHeaderHost = Just "example.com"
  }

hostHeaderProxyRequest :: Request
hostHeaderProxyRequest = defaultRequest
  { requestMethod = "GET"
  , rawPathInfo = "/resource"
  , requestHeaderHost = Just "example.com"
  , requestHeaders = [("Proxy-Connection", "keep-alive")]
  }

http2ProxyRequest :: Request
http2ProxyRequest = defaultRequest
  { requestMethod = "GET"
  , rawPathInfo = "/resource"
  , requestHeaderHost = Just "example.com"
  , requestHeaders = [("X-Scheme", "http")]
  , httpVersion = HT.http20
  , isSecure = True
  }

connectRequest :: Request
connectRequest = defaultRequest
  { requestMethod = "CONNECT"
  , rawPathInfo = "example.com:443"
  , requestHeaderHost = Just "example.com:443"
  }

fallback :: Application
fallback _req respond = respond $ responseLBS fallbackStatus [("Content-Type", "text/plain")] fallbackBody

fallbackStatus :: HT.Status
fallbackStatus = HT.mkStatus 418 "fallback"

fallbackBody :: LBS.ByteString
fallbackBody = "fallback"

authRequiredSettings :: ProxySettings
authRequiredSettings = baseSettings
  { proxyAuth = Just (const False)
  }

hiddenAuthSettings :: ProxySettings
hiddenAuthSettings = authRequiredSettings
  { hideProxyAuth = True
  }

baseSettings :: ProxySettings
baseSettings = ProxySettings
  { proxyAuth      = Nothing
  , passPrompt     = Just "hprox"
  , wsRemote       = Nothing
  , revRemoteMap   = []
  , hideProxyAuth  = False
  , naivePadding   = False
  , acmeThumbprint = Nothing
  , logger         = \_ _ -> return ()
  }
