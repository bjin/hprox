-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.

module Network.HProx.Route
  ( ReverseProxyRewrite(..)
  , ReverseRoute(..)
  , findMatchingRoute
  , fromReverseRouteTuple
  , hostMatches
  , prefixMatches
  , rewriteReverseProxyRequest
  , sortReverseRoutes
  ) where

import Data.ByteString.Char8     qualified as BS8
import Data.List                 (sortOn)
import Data.Maybe                (isJust, listToMaybe)
import Data.Ord                  (Down(..))
import Network.HTTP.Types        (RequestHeaders)
import Network.HTTP.Types.Header qualified as HT

import Network.HProx.Headers
import Network.HProx.Util

data ReverseRoute = ReverseRoute
  { routeHost     :: !(Maybe BS8.ByteString)
  , routePrefix   :: !BS8.ByteString
  , routeUpstream :: !BS8.ByteString
  }
  deriving (Eq, Show)

data ReverseProxyRewrite = ReverseProxyRewrite
  { rewriteRoute       :: !ReverseRoute
  , rewriteRawPath     :: !BS8.ByteString
  , rewriteHeaders     :: !RequestHeaders
  , rewriteRequestHost :: !(Maybe BS8.ByteString)
  , rewriteUpstream    :: !BS8.ByteString
  , rewritePort        :: !Int
  , rewriteSecure      :: !Bool
  }
  deriving (Eq, Show)

fromReverseRouteTuple :: (Maybe BS8.ByteString, BS8.ByteString, BS8.ByteString) -> ReverseRoute
fromReverseRouteTuple (host, prefix, upstream) = ReverseRoute
  { routeHost     = host
  , routePrefix   = prefix
  , routeUpstream = upstream
  }

sortReverseRoutes :: [ReverseRoute] -> [ReverseRoute]
sortReverseRoutes = sortOn $ \ReverseRoute{..} -> Down (isJust routeHost, BS8.length routePrefix)

hostMatches :: ReverseRoute -> Maybe BS8.ByteString -> Bool
hostMatches ReverseRoute{ routeHost = Nothing } _               = True
hostMatches ReverseRoute{ routeHost = Just _ } Nothing          = False
hostMatches ReverseRoute{ routeHost = Just domain } (Just host) = domain == host

prefixMatches :: ReverseRoute -> BS8.ByteString -> Bool
prefixMatches ReverseRoute{..} rawPath = routePrefix `BS8.isPrefixOf` rawPath

findMatchingRoute :: [ReverseRoute] -> Maybe BS8.ByteString -> BS8.ByteString -> Maybe ReverseRoute
findMatchingRoute routes requestHost rawPath =
  listToMaybe $ filter matches $ sortReverseRoutes routes
  where
    parsedHost = fmap hostOnly requestHost
    matches route = hostMatches route parsedHost && prefixMatches route rawPath

hostOnly :: BS8.ByteString -> BS8.ByteString
hostOnly host = maybe host fst (parseHostPort host)

rewriteReverseProxyRequest :: ReverseRoute -> RequestHeaders -> BS8.ByteString -> ReverseProxyRewrite
rewriteReverseProxyRequest route@ReverseRoute{..} requestHeaders rawPath = ReverseProxyRewrite
  { rewriteRoute       = route
  , rewriteRawPath     = BS8.drop (BS8.length routePrefix - 1) rawPath
  , rewriteHeaders     = (HT.hHost, upstreamHost) : filter keepHeader requestHeaders
  , rewriteRequestHost = Just upstreamHost
  , rewriteUpstream    = upstreamHost
  , rewritePort        = upstreamPort
  , rewriteSecure      = upstreamPort == 443
  }
  where
    (upstreamHost, upstreamPort) = parseHostPortWithDefault 80 routeUpstream

    keepHeader (name, _) = not (isProxyStripHeader name) && name /= HT.hHost

