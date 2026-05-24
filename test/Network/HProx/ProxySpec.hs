-- SPDX-License-Identifier: Apache-2.0

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
