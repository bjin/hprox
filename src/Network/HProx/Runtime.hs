-- SPDX-License-Identifier: Apache-2.0

-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.Runtime
  ( ProxyRuntime(..)
  , buildProxyApplication
  , buildProxyRuntime
  ) where

import Data.ByteString.Char8 qualified as BS8
import Data.List             (sortOn)
import Data.Maybe            (isJust)
import Data.Ord              (Down(..))
import Network.HTTP.Client   qualified as HC
import Network.Wai           (Application)

import Network.HProx.Config
import Network.HProx.Impl
import Network.HProx.Log
import Network.HProx.Route

data ProxyRuntime = ProxyRuntime
  { runtimeProxySettings :: !ProxySettings
  , runtimeReverseRoutes :: ![(Maybe BS8.ByteString, BS8.ByteString, BS8.ByteString)]
  }

buildProxyRuntime :: Config -> Logger -> Maybe (BS8.ByteString -> Bool) -> Bool -> ProxyRuntime
buildProxyRuntime Config{..} logger pauth isSSL = ProxyRuntime
  { runtimeProxySettings = ProxySettings
      { proxyAuth      = pauth
      , passPrompt     = Just _name
      , wsRemote       = _ws
      , revRemoteMap   = map fromReverseRouteTuple revSorted
      , hideProxyAuth  = _hide
      , naivePadding   = _naive && isSSL
      , acmeThumbprint = _acme
      , logger         = logger
      }
  , runtimeReverseRoutes = revSorted
  }
  where
    revSorted = sortOn (\(a,b,_) -> Down (isJust a, BS8.length b)) _rev

buildProxyApplication :: Bool -> ProxySettings -> HC.Manager -> Application -> Application
buildProxyApplication isSSL pset manager fallback =
  healthCheckProvider $
    acmeProvider pset $
      (if isSSL then forceSSL pset else id) $
        httpProxy pset manager $
          reverseProxy pset manager fallback
