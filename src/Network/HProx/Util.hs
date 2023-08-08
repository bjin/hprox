-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2023 Bin Jin. All Rights Reserved.

module Network.HProx.Util
  ( parseHostPort
  , parseHostPortWithDefault
  , responseKnownLength
  ) where

import Data.ByteString       qualified as BS
import Data.ByteString.Char8 qualified as BS8
import Data.ByteString.Lazy  qualified as LBS
import Data.Maybe            (fromMaybe)

import Network.HTTP.Types (ResponseHeaders, Status)
import Network.Wai

parseHostPort :: BS.ByteString -> Maybe (BS.ByteString, Int)
parseHostPort hostPort = do
    lastColon <- BS8.elemIndexEnd ':' hostPort
    port <- BS8.readInt (BS.drop (lastColon+1) hostPort) >>= checkPort
    return (BS.take lastColon hostPort, port)
  where
    checkPort (p, bs)
        | BS.null bs && 1 <= p && p <= 65535 = Just p
        | otherwise                          = Nothing

parseHostPortWithDefault :: Int -> BS.ByteString -> (BS.ByteString, Int)
parseHostPortWithDefault defaultPort hostPort =
    fromMaybe (hostPort, defaultPort) $ parseHostPort hostPort

responseKnownLength :: Status -> ResponseHeaders -> LBS.ByteString -> Response
responseKnownLength status headers bs = responseLBS status (headers ++ [("Content-Length", BS8.pack $ show (LBS.length bs))]) bs
