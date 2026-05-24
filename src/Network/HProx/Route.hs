-- SPDX-License-Identifier: Apache-2.0

-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.Route
  ( ReverseRoute(..)
  , fromReverseRouteTuple
  , hostMatches
  , prefixMatches
  , sortReverseRoutes
  ) where

import Data.ByteString.Char8 qualified as BS8
import Data.List             (sortOn)
import Data.Maybe            (isJust)
import Data.Ord              (Down(..))

data ReverseRoute = ReverseRoute
  { routeHost     :: !(Maybe BS8.ByteString)
  , routePrefix   :: !BS8.ByteString
  , routeUpstream :: !BS8.ByteString
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
