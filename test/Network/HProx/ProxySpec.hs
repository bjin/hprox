-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.ProxySpec
  ( spec
  ) where

import Data.ByteString.Base64     qualified as B64
import Data.ByteString.Char8      qualified as BS8
import Data.ByteString.Lazy       qualified as LBS
import Data.ByteString.Lazy.Char8 qualified as LBS8
import Data.IORef
import Network.HTTP.Client        qualified as HC
import Network.HTTP.Types         qualified as HT
import Network.HTTP.Types.Header  qualified as HT
import Network.Wai
import Network.Wai.Handler.Warp   qualified as Warp
import Network.Wai.Test
import System.Log.FastLogger      qualified as FL

import Network.HProx.Impl

import Test.Hspec

spec :: Spec
spec = do
  describe "HTTP proxy auth decisions" $ do
    it "challenges unauthorized HTTP proxy requests" $ do
      response <- runProxyApp (httpProxy authRequiredSettings) rawProxyRequest
      simpleStatus response `shouldBe` HT.status407
      lookup "Proxy-Authenticate" (simpleHeaders response) `shouldBe` Just "Basic realm=\"hprox\""

    it "accepts valid Basic credentials" $
      Warp.testWithApplication (pure observeProxyRequestApp) $ \port -> do
        response <- runProxyApp (httpProxy authorizedSettings) (proxyRequestForPort port basicAliceSecret)
        simpleStatus response `shouldBe` HT.status200

    it "rejects valid Basic credentials with the wrong password" $ do
      response <- runProxyApp (httpProxy authorizedSettings) (rawProxyRequestWithAuth $ basicCredential "alice:wrong")
      simpleStatus response `shouldBe` HT.status407

    it "rejects malformed base64 credentials even if lenient decoding would authenticate" $ do
      response <- runProxyApp (httpProxy authorizedSettings) (rawProxyRequestWithAuth "Basic !!!YWxpY2U6c2VjcmV0!!!")
      simpleStatus response `shouldBe` HT.status407

    it "rejects non-Basic credentials even when the payload is otherwise valid" $ do
      response <- runProxyApp (httpProxy authorizedSettings) (rawProxyRequestWithAuth $ "Bearer " <> B64.encode "alice:secret")
      simpleStatus response `shouldBe` HT.status407

    it "redacts proxy auth passwords in trace logs" $
      Warp.testWithApplication (pure observeProxyRequestApp) $ \port -> do
        logs <- newIORef []
        let loggingSettings = authorizedSettings
              { logger = \_ msg -> modifyIORef' logs (LBS.fromStrict (FL.fromLogStr msg) :)
              }
        response <- runProxyApp (httpProxy loggingSettings) (proxyRequestForPort port basicAliceSecret)
        simpleStatus response `shouldBe` HT.status200
        renderedLogs <- LBS.toStrict . LBS.concat . reverse <$> readIORef logs
        renderedLogs `shouldSatisfy` BS8.isInfixOf "authorized request"
        renderedLogs `shouldSatisfy` BS8.isInfixOf "alice:<redacted>"
        renderedLogs `shouldNotSatisfy` BS8.isInfixOf "secret"
        renderedLogs `shouldNotSatisfy` BS8.isInfixOf "alice:secret"

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

    it "renders HTTP proxy authorities without the default port" $ do
      renderHttpProxyAuthority (HttpProxyTarget "example.com" 80 "/")
        `shouldBe` "example.com"
      renderHttpProxyAuthority (HttpProxyTarget "example.com" 443 "/")
        `shouldBe` "example.com:443"
      renderHttpProxyAuthority (HttpProxyTarget "example.com" 8080 "/")
        `shouldBe` "example.com:8080"

  describe "HTTP proxy upstream requests" $
    it "uses absolute URI authority for Host and strips proxy boundary headers" $
      Warp.testWithApplication (pure observeProxyRequestApp) $ \port -> do
        let authority = "127.0.0.1:" <> BS8.pack (show port)
            responseBody = LBS8.lines . simpleBody
            proxiedReq = defaultRequest
              { requestMethod = "GET"
              , rawPathInfo = "http://" <> authority <> "/resource"
              , requestHeaderHost = Just "evil.example"
              , requestHeaders =
                  [ (HT.hHost, "evil.example")
                  , (HT.hProxyAuthorization, "Basic " <> B64.encode "alice:secret")
                  , ("Forwarded", "for=203.0.113.7")
                  , ("X-Forwarded-For", "203.0.113.7")
                  , ("Proxy-Connection", "keep-alive")
                  , ("cf-ray", "abc123")
                  , ("X-Real-IP", "203.0.113.7")
                  , ("User-Agent", "hprox-test")
                  ]
              }
        response <- runProxyApp (httpProxy authorizedSettings) proxiedReq
        simpleStatus response `shouldBe` HT.status200
        responseBody response
          `shouldBe` [ LBS.fromStrict authority
                     , LBS.fromStrict authority
                     , "False"
                     , "False"
                     , "False"
                     , "False"
                     , "False"
                     , "True"
                     ]
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

rawProxyRequestWithAuth :: BS8.ByteString -> Request
rawProxyRequestWithAuth auth = rawProxyRequest
  { requestHeaders = [(HT.hProxyAuthorization, auth)]
  }

proxyRequestForPort :: Int -> BS8.ByteString -> Request
proxyRequestForPort port auth =
  let authority = "127.0.0.1:" <> BS8.pack (show port)
  in (rawProxyRequestWithAuth auth)
       { rawPathInfo = "http://" <> authority <> "/resource"
       , requestHeaderHost = Just authority
       }

basicAliceSecret :: BS8.ByteString
basicAliceSecret = basicCredential "alice:secret"

basicCredential :: BS8.ByteString -> BS8.ByteString
basicCredential credential = "Basic " <> B64.encode credential

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

authorizedSettings :: ProxySettings
authorizedSettings = baseSettings
  { proxyAuth = Just (== "alice:secret")
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

observeProxyRequestApp :: Application
observeProxyRequestApp req respond = respond $ responseLBS
  HT.status200
  [("Content-Type", "text/plain")]
  (LBS8.unlines
     [ LBS.fromStrict $ maybe "" id $ requestHeaderHost req
     , LBS.fromStrict $ maybe "" id $ lookup HT.hHost (requestHeaders req)
     , LBS8.pack $ show $ hasHeader HT.hProxyAuthorization
     , LBS8.pack $ show $ hasHeader "Forwarded"
     , LBS8.pack $ show $ hasHeader "X-Forwarded-For"
     , LBS8.pack $ show $ hasHeader "Proxy-Connection"
     , LBS8.pack $ show $ hasHeader "cf-ray"
     , LBS8.pack $ show $ hasHeader "User-Agent"
     ])
  where
    hasHeader name = lookup name (requestHeaders req) /= Nothing
